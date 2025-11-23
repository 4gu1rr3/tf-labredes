#!/usr/bin/env python3
import socket
import struct
import csv
import datetime
import os

# Arquivos de log
LOG_IP = "internet.csv"
LOG_TRANS = "transporte.csv"
LOG_APP = "aplicacao.csv"

# Cria arquivos se não existirem
if not os.path.exists(LOG_IP):
    with open(LOG_IP, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "protocolo", "src", "dst", "proto_id", "info", "tamanho"])

if not os.path.exists(LOG_TRANS):
    with open(LOG_TRANS, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "protocolo", "src", "src_port", "dst", "dst_port", "tamanho"])

if not os.path.exists(LOG_APP):
    with open(LOG_APP, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "protocolo", "info"])

# Contadores
count_ipv4 = 0
count_ipv6 = 0
count_udp = 0
count_tcp = 0
count_icmp = 0
count_dns = 0
count_http = 0
count_ntp = 0
count_dhcp = 0

def print_stats():
    os.system('clear')
    print("=== MONITOR DE TUN0 ===")
    print(f"IPv4: {count_ipv4}")
    print(f"IPv6: {count_ipv6}")
    print(f"ICMP: {count_icmp}")
    print(f"TCP : {count_tcp}")
    print(f"UDP : {count_udp}")
    print(f"DNS : {count_dns}")
    print(f"HTTP: {count_http}")
    print(f"DHCP: {count_dhcp}")
    print(f"NTP : {count_ntp}")

# Abre RAW socket na tun0
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
sock.bind(("tun0", 0))

while True:
    packet, _ = sock.recvfrom(65535)
    timestamp = datetime.datetime.now().isoformat()

    eth_proto = struct.unpack("!H", packet[12:14])[0]

    # ----------------------
    #     IPv4
    # ----------------------
    if eth_proto == 0x0800:
        count_ipv4 += 1

        ip_header = packet[14:34]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        proto = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        total_len = iph[2]

        # Log internet.csv
        with open(LOG_IP, "a", newline="") as f:
            w = csv.writer(f)
            w.writerow([timestamp, "IPv4", src_ip, dst_ip, proto, "", total_len])

        # --------------------------
        #       Protocolo ICMP
        # --------------------------
        if proto == 1:
            count_icmp += 1

        # --------------------------
        #       Protocolo TCP
        # --------------------------
        elif proto == 6:
            count_tcp += 1
            tcp_header = packet[34:54]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            src_port = tcph[0]
            dst_port = tcph[1]

            # Detecta HTTP
            if dst_port == 80 or src_port == 80:
                count_http += 1
                app_proto = "HTTP"
            else:
                app_proto = ""

            # Log transporte.csv
            with open(LOG_TRANS, "a", newline="") as f:
                w = csv.writer(f)
                w.writerow([timestamp, "TCP", src_ip, src_port, dst_ip, dst_port, total_len])

            # Log aplicacao.csv
            if app_proto:
                with open(LOG_APP, "a", newline="") as f:
                    w = csv.writer(f)
                    w.writerow([timestamp, app_proto, f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"])

        # --------------------------
        #       Protocolo UDP
        # --------------------------
        elif proto == 17:
            count_udp += 1
            udp_header = packet[34:42]
            udph = struct.unpack("!HHHH", udp_header)
            src_port = udph[0]
            dst_port = udph[1]

            # Detecta DHCP (67/68), DNS (53), NTP (123)
            app_proto = ""

            if dst_port in (67, 68) or src_port in (67, 68):
                count_dhcp += 1
                app_proto = "DHCP"

            elif dst_port == 53 or src_port == 53:
                count_dns += 1
                app_proto = "DNS"

            elif dst_port == 123 or src_port == 123:
                count_ntp += 1
                app_proto = "NTP"

            # Log transporte.csv
            with open(LOG_TRANS, "a", newline="") as f:
                w = csv.writer(f)
                w.writerow([timestamp, "UDP", src_ip, src_port, dst_ip, dst_port, total_len])

            # Log aplicacao.csv
            if app_proto:
                with open(LOG_APP, "a", newline="") as f:
                    w = csv.writer(f)
                    w.writerow([timestamp, app_proto, f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"])

    # ----------------------
    #     IPv6
    # ----------------------
    elif eth_proto == 0x86DD:
        count_ipv6 += 1

        # Log básico (opcional)
        with open(LOG_IP, "a", newline="") as f:
            w = csv.writer(f)
            w.writerow([timestamp, "IPv6", "-", "-", "-", "", len(packet)])

    print_stats()
