# ids.py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import json
import sqlite3
import tempfile
import os

def analyze_pcap(file):
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
