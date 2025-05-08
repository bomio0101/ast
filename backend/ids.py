# ids.py
import sqlite3
from scapy.all import *
import json

def analyze_pcap(file):
    """分析上传的pcap文件并将结果存入数据库"""
    # 连接数据库
    conn = sqlite3.connect('network_data.db')
    cursor = conn.cursor()
    
    # 读取pcap文件
    packets = rdpcap(file)
    
    # 遍历每个数据包
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
                packet_data['flags'] = packet[TCP].flags
            
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
