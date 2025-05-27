# ids.py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import json
import sqlite3
import tempfile
import os
import threading
import time
from datetime import datetime
import ctypes
import subprocess
import sys

# 全局变量用于控制抓包状态
is_sniffing = False
sniff_thread = None

def is_admin():
    """检查程序是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_available_interfaces():
    """获取可用的网络接口列表"""
    try:
        interfaces = []
        
        if sys.platform == 'win32':
            # Windows系统使用netsh命令获取接口
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                 capture_output=True, text=True)
            if result.returncode == 0:
                # 解析netsh输出
                lines = result.stdout.split('\n')
                for line in lines[3:]:  # 跳过标题行
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 4:
                            # 获取接口状态和名称
                            status = parts[2]
                            interface_name = ' '.join(parts[3:])
                            # 添加所有接口，不管是否连接
                            interfaces.append(interface_name)
                
                # 如果没有找到接口，尝试使用scapy的方式
                if not interfaces:
                    try:
                        scapy_interfaces = get_if_list()
                        if scapy_interfaces:
                            interfaces.extend(scapy_interfaces)
                    except Exception as e:
                        logging.error(f"使用scapy获取接口失败: {str(e)}")
                
                # 如果还是没有接口，尝试使用ipconfig
                if not interfaces:
                    try:
                        ipconfig_result = subprocess.run(['ipconfig', '/all'], 
                                                      capture_output=True, text=True)
                        if ipconfig_result.returncode == 0:
                            current_adapter = None
                            for line in ipconfig_result.stdout.split('\n'):
                                if line.strip() and not line.startswith(' '):
                                    current_adapter = line.split(':')[0].strip()
                                elif current_adapter and "IPv4" in line:
                                    interfaces.append(current_adapter)
                    except Exception as e:
                        logging.error(f"使用ipconfig获取接口失败: {str(e)}")
                
                logging.info(f"找到的网络接口: {interfaces}")
                return interfaces
        else:
            # Linux/Unix系统使用ifconfig命令
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            if result.returncode == 0:
                # 解析ifconfig输出
                for line in result.stdout.split('\n'):
                    if line and not line.startswith(' '):
                        interface_name = line.split(':')[0]
                        interfaces.append(interface_name)
                return interfaces
                
        return []
    except Exception as e:
        logging.error(f"获取网络接口列表失败: {str(e)}")
        return []

def packet_callback(packet):
    """处理每个捕获的数据包"""
    try:
        packet_data = {}
        
        # 添加时间戳
        packet_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 提取基本信息
        if IP in packet:
            packet_data['src_ip'] = packet[IP].src
            packet_data['dst_ip'] = packet[IP].dst
            packet_data['protocol'] = packet[IP].proto
            
            # TCP包处理
            if TCP in packet:
                packet_data['src_port'] = packet[TCP].sport
                packet_data['dst_port'] = packet[TCP].dport
                packet_data['flags'] = str(packet[TCP].flags)
            
            # UDP包处理
            elif UDP in packet:
                packet_data['src_port'] = packet[UDP].sport
                packet_data['dst_port'] = packet[UDP].dport
            
            # 将数据转换为JSON字符串
            json_data = json.dumps(packet_data)
            
            # 存入数据库
            conn = sqlite3.connect('network_data.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO packets (data) VALUES (?)', (json_data,))
            conn.commit()
            conn.close()
            
    except Exception as e:
        logging.error(f"处理数据包时出现错误: {str(e)}")

def start_sniffing(interface=None):
    """开始实时抓包"""
    global is_sniffing, sniff_thread
    
    if is_sniffing:
        return False, "已经在抓包中"
    
    # 检查管理员权限
    if not is_admin():
        logging.error("需要管理员权限才能进行抓包")
        return False, "需要管理员权限才能进行抓包"
    
    # 如果没有指定接口，尝试使用默认接口
    if interface is None:
        interfaces = get_available_interfaces()
        if not interfaces:
            logging.error("未找到可用的网络接口")
            return False, "未找到可用的网络接口"
        interface = interfaces[0]  # 使用第一个可用接口
    
    # 验证接口是否可用
    try:
        count=10
        if sys.platform == 'win32':
            result = subprocess.run(['netsh', 'interface', 'show', 'interface', interface], 
                                 capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"接口 {interface} 不可用")
                return False, f"接口 {interface} 不可用"
    except Exception as e:
        logging.error(f"检查接口时出错: {str(e)}")
        return False, f"检查接口时出错: {str(e)}"
    
    def sniff_packets():
        global is_sniffing
        try:
            is_sniffing = True
            logging.info(f"开始在接口 {interface} 上抓包")
            
            # 使用更安全的抓包方式
            try:
                sniff(iface=interface, 
                      prn=packet_callback, 
                      store=0, 
                      timeout=0,
                      filter="ip",  # 只抓取IP包
                      stop_filter=lambda x: not is_sniffing)  # 添加停止条件
            except Exception as e:
                logging.error(f"抓包过程中出现错误: {str(e)}")
                is_sniffing = False
                return False, f"抓包失败: {str(e)}"
                
        except Exception as e:
            logging.error(f"抓包线程出现错误: {str(e)}")
            is_sniffing = False
            return False, f"抓包失败: {str(e)}"
    
    try:
        # 在新线程中启动抓包
        sniff_thread = threading.Thread(target=sniff_packets)
        sniff_thread.daemon = True  # 设置为守护线程
        sniff_thread.start()
        
        # 等待一小段时间确认抓包是否成功启动
        time.sleep(0.5)
        if not is_sniffing:
            logging.error("抓包启动失败")
            return False, "抓包启动失败"
            
        logging.info(f"成功开始在接口 {interface} 上抓包")
        return True, f"开始抓包 (接口: {interface})"
    except Exception as e:
        logging.error(f"启动抓包线程失败: {str(e)}")
        is_sniffing = False
        return False, f"启动抓包失败: {str(e)}"

def stop_sniffing():
    """停止实时抓包"""
    global is_sniffing, sniff_thread
    
    if not is_sniffing:
        return False, "没有正在进行的抓包"
    
    try:
        # 停止抓包
        is_sniffing = False
        if sniff_thread:
            sniff_thread.join(timeout=1)
        return True, "停止抓包"
    except Exception as e:
        logging.error(f"停止抓包失败: {str(e)}")
        return False, f"停止抓包失败: {str(e)}"

def get_sniffing_status():
    """获取抓包状态"""
    return is_sniffing

def analyze_pcap(file):
    """分析上传的pcap文件"""
    try:
        # 使用临时文件
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
            file.save(tmp.name)
            # 读取pcap文件
            packets = rdpcap(tmp.name)
            
            # 连接数据库
            conn = sqlite3.connect('network_data.db')
            cursor = conn.cursor()
            
            for packet in packets:
                packet_data = {}
                
                # 添加时间戳
                packet_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # 提取基本信息
                if IP in packet:
                    packet_data['src_ip'] = packet[IP].src
                    packet_data['dst_ip'] = packet[IP].dst
                    packet_data['protocol'] = packet[IP].proto
                    
                    # TCP包处理
                    if TCP in packet:
                        packet_data['src_port'] = packet[TCP].sport
                        packet_data['dst_port'] = packet[TCP].dport
                        packet_data['flags'] = str(packet[TCP].flags)
                    
                    # UDP包处理
                    elif UDP in packet:
                        packet_data['src_port'] = packet[UDP].sport
                        packet_data['dst_port'] = packet[UDP].dport
                
                # 将数据转换为JSON字符串
                json_data = json.dumps(packet_data)
                
                # 存入数据库
                cursor.execute('INSERT INTO packets (data) VALUES (?)', (json_data,))
            
            # 提交并关闭连接
            conn.commit()
            conn.close()
            
        # 删除临时文件
        os.unlink(tmp.name)
        
    except Exception as e:
        logging.error(f"分析过程中出现错误: {str(e)}")
        raise e
