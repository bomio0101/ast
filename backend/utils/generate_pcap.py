from scapy.all import *
import random
import time
import os

def generate_test_pcap(filename='test.pcap', packet_count=100):
    # 确保目录存在
    os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
    
    packets = []
    
    # 生成一些常见的网络流量包
    for _ in range(packet_count):
        # 随机源IP和目标IP
        src_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        dst_ip = f"10.0.{random.randint(1,255)}.{random.randint(1,255)}"
        
        # 随机源端口和目标端口
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 53])
        
        # 创建数据包
        if random.random() > 0.5:
            # TCP包
            packet = IP(src=src_ip, dst=dst_ip)/\
                    TCP(sport=src_port, dport=dst_port)/\
                    Raw(load="TEST"*random.randint(1,10))
        else:
            # UDP包
            packet = IP(src=src_ip, dst=dst_ip)/\
                    UDP(sport=src_port, dport=dst_port)/\
                    Raw(load="TEST"*random.randint(1,10))
        
        packets.append(packet)
        time.sleep(0.01)  # 添加一些时间间隔
    
    # 保存为PCAP文件
    wrpcap(filename, packets)
    print(f"已生成测试PCAP文件: {filename}")

if __name__ == "__main__":
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(os.path.dirname(current_dir), 'data')
    pcap_file = os.path.join(data_dir, 'test_traffic.pcap')
    generate_test_pcap(pcap_file)