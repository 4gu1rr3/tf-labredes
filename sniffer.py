import socket
import struct
import time

def parse_ip_header(packet):
    # Pega os primeiros 20 bytes (Cabeçalho IP padrão)
    # ! = Network Endian (Big Endian)
    # B = 1 byte (Version + IHL)
    # B = 1 byte (TOS)
    # H = 2 bytes (Total Length)
    # ... e assim por diante
    # 4s = 4 bytes string (Endereço IP)
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4  # Tamanho do cabeçalho em bytes
    
    protocol = ip_header[6] # 6 = TCP, 17 = UDP, 1 = ICMP
    s_addr = socket.inet_ntoa(ip_header[8])
    d_addr = socket.inet_ntoa(ip_header[9])
    
    return protocol, s_addr, d_addr, iph_length

def main():
    # Escuta na interface tun0
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind(("tun0", 0))
    
    print("Monitorando tun0... (Pressione Ctrl+C para parar)")
    
    while True:
        raw_data, addr = sock.recvfrom(65535)
        
        # 1. Decodificar IP (Camada de Rede - CSV 1)
        try:
            proto, src, dst, ip_offset = parse_ip_header(raw_data)
            
            # Mapeamento simples de protocolos
            proto_name = "OUTRO"
            if proto == 1: proto_name = "ICMP"
            elif proto == 6: proto_name = "TCP"
            elif proto == 17: proto_name = "UDP"
            
            print(f"[IP] {src} -> {dst} | Proto: {proto_name}")

            # 2. Decodificar Transporte (Se for TCP ou UDP)
            # Os dados de transporte começam logo após o cabeçalho IP
            if proto == 6 or proto == 17:
                transport_data = raw_data[ip_offset:]
                # As portas (Source/Dest) são os primeiros 4 bytes tanto no TCP quanto UDP
                src_port, dst_port = struct.unpack('!HH', transport_data[:4])
                print(f"   [TRANS] Porta Origem: {src_port} -> Destino: {dst_port}")
                
        except Exception as e:
            print(f"Erro ao processar pacote: {e}")

if __name__ == "__main__":
    main()