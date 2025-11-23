import socket
import struct
import sys
import time
import csv
import os
import threading
from datetime import datetime

# --- CONFIGURAÇÕES ---
INTERFACE = "tun0" # Pode ser sobrescrito via argumento

LOG_INTERNET = "camada_internet.csv"
LOG_TRANSPORTE = "camada_transporte.csv"
LOG_APLICACAO = "camada_aplicacao.csv"

# Variável de controle para parar as threads suavemente
running = True

# Contadores compartilhados
stats = {
    "total_pacotes": 0,
    "ipv4": 0, "ipv6": 0, "icmp": 0,
    "tcp": 0, "udp": 0,
    "http": 0, "dns": 0, "dhcp": 0, "ntp": 0,
    "outros_app": 0
}

def inicializar_logs():
    """Garante que os arquivos CSV existam com cabeçalhos."""
    headers = {
        LOG_INTERNET: ["Timestamp", "Protocolo_L3", "IP_Origem", "IP_Destino", "ID_Proto", "Info_Extra", "Tamanho_Bytes"],
        LOG_TRANSPORTE: ["Timestamp", "Protocolo_L4", "IP_Origem", "Porta_Origem", "IP_Destino", "Porta_Destino", "Tamanho_Bytes"],
        LOG_APLICACAO: ["Timestamp", "Protocolo_App", "Info_Protocolo"]
    }
    for arquivo, colunas in headers.items():
        if not os.path.exists(arquivo):
            try:
                with open(arquivo, 'w', newline='') as f:
                    csv.writer(f).writerow(colunas)
            except: pass

def log_csv(arquivo, dados):
    """Escreve no CSV (Thread Safe o suficiente para este uso)."""
    try:
        with open(arquivo, 'a', newline='') as f:
            csv.writer(f).writerow(dados)
    except: pass

def exibir_stats_loop():
    """
    THREAD 2: Responsável APENAS por atualizar a tela.
    Não bloqueia a captura de pacotes.
    """
    global running
    while running:
        # Código ANSI para limpar a tela e mover cursor para o topo (MUITO RÁPIDO)
        print("\033[H\033[J", end="")
        
        print("="*50)
        print("    MONITOR DE TRÁFEGO DE REDE    ")
        print("="*50)
        print(f"Total de Pacotes: {stats['total_pacotes']}")
        print("-" * 50)
        print("CAMADA DE REDE (L3):")
        print(f"  IPv4: {stats['ipv4']:<6} | IPv6: {stats['ipv6']:<6} | ICMP: {stats['icmp']:<6}")
        print("-" * 50)
        print("CAMADA DE TRANSPORTE (L4):")
        print(f"  TCP:  {stats['tcp']:<6} | UDP:  {stats['udp']:<6}")
        print("-" * 50)
        print("CAMADA DE APLICAÇÃO (L7):")
        print(f"  HTTP: {stats['http']:<6} | DNS: {stats['dns']:<6}")
        print(f"  DHCP: {stats['dhcp']:<6} | NTP: {stats['ntp']:<6}")
        print("="*50)
        print("Pressione Ctrl+C para encerrar.")
        
        # Atualiza a tela a cada 0.5 segundos
        time.sleep(0.5)

def parse_packet(packet_data):
    """Analisa o pacote e atualiza stats + logs."""
    stats['total_pacotes'] += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    packet_len = len(packet_data)

    if packet_len < 20: return

    try:
        # --- L3: IP ---
        version = packet_data[0] >> 4
        ihl = packet_data[0] & 0xF
        iph_len = ihl * 4

        if version != 4:
            stats['ipv6'] += 1
            log_csv(LOG_INTERNET, [timestamp, "IPv6", "-", "-", "-", "-", packet_len])
            return

        stats['ipv4'] += 1
        iph = struct.unpack('!BBHHHBBH4s4s', packet_data[:20])
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, "Outro")
        
        extra_icmp = ""
        if protocol == 1:
            stats['icmp'] += 1
            if len(packet_data) >= iph_len + 2:
                t, c = struct.unpack('!BB', packet_data[iph_len:iph_len+2])
                extra_icmp = f"Type:{t} Code:{c}"
                
        log_csv(LOG_INTERNET, [timestamp, f"IPv4({proto_name})", src_ip, dst_ip, protocol, extra_icmp, packet_len])

        if protocol == 1: return

        # --- L4: Transporte ---
        l4_data = packet_data[iph_len:]
        if len(l4_data) < 4: return
        
        src_port, dst_port = struct.unpack('!HH', l4_data[:4])
        l4_name = ""
        payload_start_offset = 0

        if protocol == 6: # TCP
            if len(l4_data) < 20: return
            stats['tcp'] += 1
            l4_name = "TCP"
            payload_start_offset = (l4_data[12] >> 4) * 4
        elif protocol == 17: # UDP
            if len(l4_data) < 8: return
            stats['udp'] += 1
            l4_name = "UDP"
            payload_start_offset = 8
        else: return

        log_csv(LOG_TRANSPORTE, [timestamp, l4_name, src_ip, src_port, dst_ip, dst_port, packet_len])

        # --- L7: Aplicação ---
        if len(l4_data) > payload_start_offset:
            payload = l4_data[payload_start_offset:]
            ports = [src_port, dst_port]
            app_proto = None
            info = ""
            
            # Tenta decodificar string para HTTP
            try: txt = payload[:60].decode('utf-8', errors='ignore')
            except: txt = ""

            if 80 in ports or 8080 in ports:
                app_proto = "HTTP"; stats['http'] += 1
                info = txt.split('\r\n')[0] if txt else "HTTP Data"
            elif 53 in ports:
                app_proto = "DNS"; stats['dns'] += 1; info = "DNS Query/Resp"
            elif 67 in ports or 68 in ports:
                app_proto = "DHCP"; stats['dhcp'] += 1; info = "DHCP Packet"
            elif 123 in ports:
                app_proto = "NTP"; stats['ntp'] += 1; info = "Time Sync"

            if app_proto:
                log_csv(LOG_APLICACAO, [timestamp, app_proto, info])

    except Exception:
        pass

def start_sniffer_thread(interface):
    """THREAD 1: Loop de Captura (Alta Prioridade)."""
    global running
    try:
        # Aumentamos o buffer do socket para evitar drops (2MB)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
        s.bind((interface, 0))
    except Exception as e:
        print(f"ERRO FATAL: {e}")
        running = False
        return

    while running:
        try:
            # Captura
            raw_data, _ = s.recvfrom(65535)
            # Processa imediatamente
            parse_packet(raw_data)
        except Exception:
            pass

def main():
    global running
    
    if len(sys.argv) < 2:
        target_interface = "tun0"
    else:
        target_interface = sys.argv[1]

    inicializar_logs()
    
    print(f"Iniciando sniffer na {target_interface}...")
    time.sleep(1)

    # 1. Inicia a Thread de Captura (Background)
    t_sniff = threading.Thread(target=start_sniffer_thread, args=(target_interface,))
    t_sniff.daemon = True # Morre se o programa principal morrer
    t_sniff.start()

    # 2. Inicia o Loop de Visualização (Main Thread)
    try:
        exibir_stats_loop()
    except KeyboardInterrupt:
        running = False
        print("\nParando Threads... Aguarde.")
        time.sleep(1)
        sys.exit(0)

if __name__ == "__main__":
    main()