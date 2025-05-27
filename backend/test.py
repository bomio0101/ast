# standalone_scapy_test.py (或您的 test.py)
from scapy.all import sniff, conf # 仍然可以导入 conf，只是不访问 pcap_name
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

INTERFACE_TO_TEST = "WLAN 2" 
PACKET_COUNT_TO_SNIFF = 10

def simple_packet_printer(packet):
    logging.info(f"捕获到数据包: {packet.summary()}")
    # packet.show() 

if __name__ == "__main__":
    logging.info(f"将尝试在接口 '{INTERFACE_TO_TEST}' 上使用 Scapy 抓取 {PACKET_COUNT_TO_SNIFF} 个 IP 数据包...")
    
    # logging.info(f"Scapy 使用的 Pcap 名称: {conf.pcap_name}") # <<-- 注释掉或删除这一行
    # 您可以尝试打印其他有用的 conf 属性，如果需要的话，例如：
    # logging.info(f"Scapy L3socket 配置: {conf.L3socket}")
    # logging.info(f"Scapy iface 配置: {conf.iface}") # Scapy的默认/当前接口

    try:
        logging.info("尝试1: 带 filter='ip'")
        sniff(iface=INTERFACE_TO_TEST, prn=simple_packet_printer, count=PACKET_COUNT_TO_SNIFF, filter="ip")
        logging.info(f"尝试1 结束。")

        logging.info("-" * 30)

        logging.info("尝试2: 不带 filter (捕获所有类型的帧)")
        sniff(iface=INTERFACE_TO_TEST, prn=simple_packet_printer, count=PACKET_COUNT_TO_SNIFF)
        logging.info(f"尝试2 结束。")

    except Exception as e:
        logging.error(f"在接口 '{INTERFACE_TO_TEST}' 上使用 Scapy 直接抓包时发生错误: {e}", exc_info=True)