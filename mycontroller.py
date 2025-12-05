#!/usr/bin/env python3
import argparse
import os
import sys
from time import sleep
import datetime

import grpc

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections

# 主机信息 (来自 topology.json)
H1_IP = "10.0.1.1"
H1_MAC = "08:00:00:00:01:11"
H2_IP = "10.0.2.2"
H2_MAC = "08:00:00:00:02:22"
H3_IP = "10.0.3.3"
H3_MAC = "08:00:00:00:03:33"

# 隧道ID定义 (根据图片更新)
TID_S1_S2 = 100
TID_S2_S1 = 101
TID_S1_S3 = 200
TID_S3_S1 = 201
TID_S2_S3 = 300
TID_S3_S2 = 301

# 交换机端口定义 (来自 topology.json)
S1_H1_PORT = 1
S1_S2_PORT = 2
S1_S3_PORT = 3

S2_H2_PORT = 1 # port 1 on s2 connects to h2
S2_S1_PORT = 2
S2_S3_PORT = 3

S3_H3_PORT = 1 # port 1 on s3 connects to h3
S3_S1_PORT = 2
S3_S2_PORT = 3


def writeL3ForwardRule(p4info_helper, sw, dst_ip_addr, dst_eth_addr, port):
    """
    安装 L3 转发规则 (ipv4_forward)
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": port
        })
    sw.WriteTableEntry(table_entry)
    print(f"Installed L3 forward rule on {sw.name}: {dst_ip_addr} -> port {port}")

def writeTunnelIngressRule(p4info_helper, sw, dst_ip_addr, tunnel_id):
    """
    安装隧道封装规则 (myTunnel_ingress)
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.myTunnel_ingress",
        action_params={
            "dst_id": tunnel_id,
        })
    sw.WriteTableEntry(table_entry)
    print(f"Installed ingress tunnel rule on {sw.name}: {dst_ip_addr} -> tid {tunnel_id}")

def writeTunnelTransitRule(p4info_helper, sw, tunnel_id, port):
    """
    安装隧道中转规则 (myTunnel_forward)
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.myTunnel_exact",
        match_fields={
            "hdr.myTunnel.dst_id": tunnel_id
        },
        action_name="MyIngress.myTunnel_forward",
        action_params={
            "port": port
        }
    )
    sw.WriteTableEntry(table_entry)
    print(f"Installed transit tunnel rule on {sw.name}: tid {tunnel_id} -> port {port}")

def writeTunnelEgressRule(p4info_helper, sw, tunnel_id, dst_eth_addr, port):
    """
    安装隧道解封装规则 (myTunnel_egress)
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.myTunnel_exact",
        match_fields={
            "hdr.myTunnel.dst_id": tunnel_id
        },
        action_name="MyIngress.myTunnel_egress",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": port
        })
    sw.WriteTableEntry(table_entry)
    print(f"Installed egress tunnel rule on {sw.name}: tid {tunnel_id} -> {dst_eth_addr} @ port {port}")


def readTableRules(p4info_helper, sw):
    """
    读取并打印交换机上的所有表项。
    """
    print(f'\n----- Reading tables rules for {sw.name} -----')
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_id = entry.table_id
            table_name = p4info_helper.get_tables_name(table_id)
            print(f"Table: {table_name}")
            print(entry)
            print('-----')

def log_to_file(filepath, message):
    """
    将消息追加写入指定文件
    """
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(message + '\n')

def read_counter(p4info_helper, sw, counter_name, index):
    """
    读取单个计数器条目并返回 (packet_count, byte_count)
    """
    try:
        for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
            for entity in response.entities:
                counter = entity.counter_entry
                return (counter.data.packet_count, counter.data.byte_count)
    except Exception as e:
        print(f"Error reading counter {counter_name}[{index}] from {sw.name}: {e}", file=sys.stderr)
    # 如果没有找到条目或发生错误，返回 0
    return (0, 0)

def process_link_counters(p4info_helper, sw_src, sw_dst, tunnel_id, log_file):
    """
    读取、打印并记录一个单向链路的计数器 (Ingress 和 Egress)
    """
    timestamp = datetime.datetime.now().isoformat()
    sw_src_name = sw_src.name
    sw_dst_name = sw_dst.name

    print(f"\n----- {sw_src_name} -> {sw_dst_name} -----")
    
    # Ingress (发送)
    p_ing, b_ing = read_counter(p4info_helper, sw_src, "MyIngress.ingressTunnelCounter", tunnel_id)
    console_msg_ing = f"{sw_src_name} MyIngress.ingressTunnelCounter {tunnel_id}: {p_ing} packets ({b_ing} bytes)"
    file_msg_ing = f"{timestamp} {sw_src_name}发送{p_ing}个包, 计数器编号为: {tunnel_id}"
    print(console_msg_ing)
    log_to_file(log_file, file_msg_ing)
    
    # Egress (接收)
    p_eg, b_eg = read_counter(p4info_helper, sw_dst, "MyIngress.egressTunnelCounter", tunnel_id)
    console_msg_eg = f"{sw_dst_name} MyIngress.egressTunnelCounter {tunnel_id}: {p_eg} packets ({b_eg} bytes)"
    file_msg_eg = f"{timestamp} {sw_dst_name}收到{p_eg}个包, 计数器编号为: {tunnel_id}"
    print(console_msg_eg)
    log_to_file(log_file, file_msg_eg)

def main(p4info_file_path, bmv2_file_path):
    # 实例化 P4Info 助手
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    # 定义日志文件路径 (与 mycontroller.py 在同一目录)
    s1s2_log = "S1S2.txt"
    s1s3_log = "S1S3.txt"
    s2s3_log = "S2S3.txt"
    
    # 清空旧的日志文件
    open(s1s2_log, 'w').close()
    open(s1s3_log, 'w').close()
    open(s2s3_log, 'w').close()

    try:
        # 为 s1, s2, s3 创建交换机连接
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # 建立主控制器连接
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # 在交换机上安装 P4 程序
        print("Installing P4 Program on s1...")
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program on s1")
        print("Installing P4 Program on s2...")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program on s2")
        print("Installing P4 Program on s3...")
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program on s3")

        # --- 安装流规则 ---

        print("\n--- Installing L3 Forwarding Rules (Local Delivery) ---")
        writeL3ForwardRule(p4info_helper, s1, H1_IP, H1_MAC, S1_H1_PORT)
        writeL3ForwardRule(p4info_helper, s2, H2_IP, H2_MAC, S2_H2_PORT)
        writeL3ForwardRule(p4info_helper, s3, H3_IP, H3_MAC, S3_H3_PORT)

        print("\n--- Installing Tunnel Rules for s1 <-> s2 ---")
        # s1 -> s2 (TID 100)
        writeTunnelIngressRule(p4info_helper, s1, H2_IP, TID_S1_S2)
        writeTunnelTransitRule(p4info_helper, s1, TID_S1_S2, S1_S2_PORT) # s1 -> s2
        writeTunnelEgressRule(p4info_helper, s2, TID_S1_S2, H2_MAC, S2_H2_PORT)
        
        # s2 -> s1 (TID 101)
        writeTunnelIngressRule(p4info_helper, s2, H1_IP, TID_S2_S1)
        writeTunnelTransitRule(p4info_helper, s2, TID_S2_S1, S2_S1_PORT) # s2 -> s1
        writeTunnelEgressRule(p4info_helper, s1, TID_S2_S1, H1_MAC, S1_H1_PORT)
        
        print("\n--- Installing Tunnel Rules for s1 <-> s3 ---")
        # s1 -> s3 (TID 200)
        writeTunnelIngressRule(p4info_helper, s1, H3_IP, TID_S1_S3)
        writeTunnelTransitRule(p4info_helper, s1, TID_S1_S3, S1_S3_PORT) # s1 -> s3
        writeTunnelEgressRule(p4info_helper, s3, TID_S1_S3, H3_MAC, S3_H3_PORT)

        # s3 -> s1 (TID 201)
        writeTunnelIngressRule(p4info_helper, s3, H1_IP, TID_S3_S1)
        writeTunnelTransitRule(p4info_helper, s3, TID_S3_S1, S3_S1_PORT) # s3 -> s1
        writeTunnelEgressRule(p4info_helper, s1, TID_S3_S1, H1_MAC, S1_H1_PORT)

        print("\n--- Installing Tunnel Rules for s2 <-> s3 ---")
        # s2 -> s3 (TID 300)
        writeTunnelIngressRule(p4info_helper, s2, H3_IP, TID_S2_S3)
        writeTunnelTransitRule(p4info_helper, s2, TID_S2_S3, S2_S3_PORT) # s2 -> s3
        writeTunnelEgressRule(p4info_helper, s3, TID_S2_S3, H3_MAC, S3_H3_PORT)

        # s3 -> s2 (TID 301)
        writeTunnelIngressRule(p4info_helper, s3, H2_IP, TID_S3_S2)
        writeTunnelTransitRule(p4info_helper, s3, TID_S3_S2, S3_S2_PORT) # s3 -> s2
        writeTunnelEgressRule(p4info_helper, s2, TID_S3_S2, H2_MAC, S2_H2_PORT)

        # (可选) 读取已安装的规则
        # readTableRules(p4info_helper, s1)
        # readTableRules(p4info_helper, s2)
        # readTableRules(p4info_helper, s3)

        # 循环读取计数器
        while True:
            sleep(2)
            print(f'\n----- Reading tunnel counters ({datetime.datetime.now().isoformat()}) -----')
            
            # s1 <-> s2
            process_link_counters(p4info_helper, s1, s2, TID_S1_S2, s1s2_log)
            process_link_counters(p4info_helper, s2, s1, TID_S2_S1, s1s2_log)

            # s1 <-> s3
            process_link_counters(p4info_helper, s1, s3, TID_S1_S3, s1s3_log)
            process_link_counters(p4info_helper, s3, s1, TID_S3_S1, s1s3_log)

            # s2 <-> s3
            process_link_counters(p4info_helper, s2, s3, TID_S2_S3, s2s3_log)
            process_link_counters(p4info_helper, s3, s2, TID_S3_S2, s2s3_log)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/advanced_tunnel.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print(f"\np4info file not found: {args.p4info}\nHave you run 'make'?")
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print(f"\nBMv2 JSON file not found: {args.bmv2_json}\nHave you run 'make'?")
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
