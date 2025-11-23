import socket
import struct
import sys
import time
import csv
import os
from datetime import datetime

# Configurações de Arquivos de Log conforme especificado no PDF
LOG_INTERNET = "camada_internet.csv"
LOG_TRANSPORTE = "camada_transporte.csv"
LOG_APLICACAO = "camada_aplicacao.csv"

# Contadores para estatísticas em tempo real
stats = {
    "total_pacotes": 0,
    "ipv4": 0,
    "ipv6": 0,
    "icmp": 0,
    "tcp": 0,
    "udp": 0,
    "http": 0,
    "dns": 0,
    "dhcp": 0,
    "outros_app": 0
}

def inicializar_logs():
    """Cria os arquivos CSV com os cabeçalhos se não existirem."""
    if not os.path.exists(LOG_INTERNET):
        with open(LOG_INTERNET, 'w', newline='') as f:
            writer = csv.writer(f)
            # Colunas baseadas no PDF 
            writer.writerow(["Timestamp", "Protocolo_L3", "IP_Origem", "IP_Destino", "ID_Proto", "Info_Extra", "Tamanho_Bytes"])

    if not os.path.exists(LOG_TRANSPORTE):
        with open(LOG_TRANSPORTE, 'w', newline='') as f:
            writer = csv.writer(f)
            # Colunas baseadas no PDF 
            writer.writerow(["Timestamp", "Protocolo_L4", "IP_Origem", "Porta_Origem", "IP_Destino", "Porta_Destino", "Tamanho_Bytes"])

    if not os.path.exists(LOG_APLICACAO):
        with open(LOG_APLICACAO, 'w', newline='') as f:
            writer = csv.writer(f)
            # Colunas baseadas no PDF 
            writer.writerow(["Timestamp", "Protocolo_App", "Info_Protocolo"])

def log_csv(arquivo, dados):
    """Escreve uma linha no arquivo CSV especificado."""
    try:
        with open(arquivo, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(dados)
    except Exception as e:
        print(f"[Erro ao gravar log] {e}")

def exibir_stats():
    """Exibe interface de texto simples com contadores."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print("="*40)
    print("    MONITOR DE TRÁFEGO - T2 REDES")
    print("="*40)
    print(f"Total de Pacotes Capturados: {stats['total_pacotes']}")
    print("-" * 40)
    print("CAMADA DE REDE (L3):")
    print(f"  IPv4: {stats['ipv4']} | IPv6: {stats['ipv6']} | ICMP: {stats['icmp']}")
    print("-" * 40)
    print("CAMADA DE TRANSPORTE (L4):")
    print(f"  TCP:  {stats['tcp']} | UDP:  {stats['udp']}")
    print("-" * 40)
    print("CAMADA DE APLICAÇÃO (L7):")
    print(f"  HTTP: {stats['http']} | DNS: {stats['dns']} | DHCP: {stats['dhcp']}")
    print("="*40)
    print("Pressione Ctrl+C para encerrar.")

def parse_packet(packet_data):
    stats['total_pacotes'] += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    packet_len = len(packet_data)

    # 1. CAMADA DE REDE (IP)
    # Como estamos lendo de tun0 (L3 tunnel), o pacote começa no cabeçalho IP
    # O primeiro byte contém Versão (4 bits) e IHL (4 bits)
    try:
        version_ihl = packet_data[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        if version != 4:
            # Simples suporte a IPv6 apenas para contagem, foco no IPv4 para parsing detalhado
            stats['ipv6'] += 1
            log_csv(LOG_INTERNET, [timestamp, "IPv6", "-", "-", "-", "Não suportado detalhadamente", packet_len])
            return

        stats['ipv4'] += 1
        
        # Desempacota cabeçalho IPv4 (20 bytes padrão)
        # ! = Network Endian (Big Endian), B=Byte, H=Short(2), s=String/Char
        iph = struct.unpack('!BBHHHBBH4s4s', packet_data[:20])
        
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        
        proto_name = "Outro"
        if protocol == 1: proto_name = "ICMP"
        elif protocol == 6: proto_name = "TCP"
        elif protocol == 17: proto_name = "UDP"

        # Log Camada Internet [cite: 25]
        info_icmp = "Type/Code: " + str(packet_data[iph_length:iph_length+2].hex()) if protocol == 1 else ""
        if protocol == 1: stats['icmp'] += 1
        
        log_csv(LOG_INTERNET, [timestamp, "IPv4", s_addr, d_addr, protocol, info_icmp, packet_len])

        # Se for ICMP, para por aqui
        if protocol == 1:
            return

        # 2. CAMADA DE TRANSPORTE
        l4_start = iph_length
        src_port = 0
        dst_port = 0
        l4_proto_name = ""

        payload_start = 0 # Onde começa os dados da aplicação

        if protocol == 6: # TCP
            stats['tcp'] += 1
            l4_proto_name = "TCP"
            # Cabeçalho TCP tem 20 bytes base
            tcph = struct.unpack('!HHLLBBHHH', packet_data[l4_start:l4_start+20])
            src_port = tcph[0]
            dst_port = tcph[1]
            data_offset = tcph[4] >> 4
            payload_start = l4_start + (data_offset * 4)
            
        elif protocol == 17: # UDP
            stats['udp'] += 1
            l4_proto_name = "UDP"
            # Cabeçalho UDP tem 8 bytes
            udph = struct.unpack('!HHHH', packet_data[l4_start:l4_start+8])
            src_port = udph[0]
            dst_port = udph[1]
            payload_start = l4_start + 8
        
        else:
            return # Protocolo não é TCP nem UDP

        # Log Camada Transporte [cite: 32]
        log_csv(LOG_TRANSPORTE, [timestamp, l4_proto_name, s_addr, src_port, d_addr, dst_port, packet_len])

        # 3. CAMADA DE APLICAÇÃO
        # Identificação básica por porta e análise simples de payload
        app_proto = "Outro"
        app_info = f"SrcPort: {src_port} -> DstPort: {dst_port}"

        # Tenta extrair payload (dados) como texto (se possível)
        try:
            payload = packet_data[payload_start:]
            payload_text = payload.decode('utf-8', errors='ignore')
        except:
            payload_text = ""

        # Verifica HTTP (Porta 80 ou 8080) ou payload típico
        if src_port in [80, 8080] or dst_port in [80, 8080] or "HTTP" in payload_text:
            app_proto = "HTTP"
            stats['http'] += 1
            # Pega a primeira linha do HTTP (ex: GET /index.html HTTP/1.1)
            first_line = payload_text.split('\r\n')[0][:50] 
            app_info = f"HTTP Info: {first_line}"

        # Verifica DNS (Porta 53)
        elif src_port == 53 or dst_port == 53:
            app_proto = "DNS"
            stats['dns'] += 1
            app_info = "Query/Response DNS"

        # Verifica DHCP (Portas 67 server, 68 client)
        elif src_port in [67, 68] or dst_port in [67, 68]:
            app_proto = "DHCP"
            stats['dhcp'] += 1
            app_info = "Transação DHCP"
        
        # Verifica NTP (Porta 123)
        elif src_port == 123 or dst_port == 123:
            app_proto = "NTP"
            app_info = "Sincronização de Tempo"

        if app_proto != "Outro":
            # Log Camada Aplicação [cite: 42]
            log_csv(LOG_APLICACAO, [timestamp, app_proto, app_info])

    except Exception as e:
        # Captura erros de parsing (pacotes malformados ou curtos demais)
        return

def main():
    # Validação de argumentos
    if len(sys.argv) < 2:
        print("Uso: python3 monitor.py <interface>")
        print("Exemplo: sudo python3 monitor.py tun0")
        sys.exit(1)

    interface = sys.argv[1]
    print(f"Iniciando monitor na interface: {interface}")
    
    inicializar_logs()

    try:
        # Criação do RAW Socket 
        # socket.ntohs(0x0003) = ETH_P_ALL (Captura tudo)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        
        # Vincula o socket à interface específica (ex: tun0)
        s.bind((interface, 0))
        
    except PermissionError:
        print("ERRO: Permissão negada. Execute com sudo!")
        sys.exit(1)
    except Exception as e:
        print(f"ERRO ao criar socket: {e}")
        sys.exit(1)

    # Loop principal
    try:
        while True:
            # Recebe pacote (buffer max 65565)
            raw_data, addr = s.recvfrom(65565)
            
            # Processa o pacote
            parse_packet(raw_data)
            
            # Atualiza a tela a cada 10 pacotes para não piscar demais
            if stats['total_pacotes'] % 5 == 0:
                exibir_stats()

    except KeyboardInterrupt:
        print("\nMonitoramento encerrado pelo usuário.")
        sys.exit(0)

if __name__ == "__main__":
    main()