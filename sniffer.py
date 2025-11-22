import socket
import struct
import sys

def main():
    # 1. Criar o Raw Socket
    # PF_PACKET permite acesso direto ao driver da placa de rede
    # 0x0003 (ETH_P_ALL) diz ao kernel: "me dê pacotes de TODOS os protocolos"
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except PermissionError:
        print("Erro: Você precisa rodar como root/sudo!")
        sys.exit(1)

    # 2. Bind na interface tun0
    # O documento especifica que devemos monitorar a 'tun0' no proxy [cite: 23]
    interface = "tun0"
    try:
        sock.bind((interface, 0))
        print(f"[*] Escutando na interface {interface}...")
    except OSError:
        print(f"Erro: Interface {interface} não encontrada. O túnel está rodando?")
        sys.exit(1)

    # 3. Loop de captura
    while True:
        # Recebe os dados (buffer de 65535 bytes é suficiente para qualquer pacote IP)
        raw_data, addr = sock.recvfrom(65535)
        
        # Apenas para teste inicial: mostre o tamanho e os primeiros bytes (hex)
        print(f"Pacote capturado! Tamanho: {len(raw_data)} bytes")
        print(f"Primeiros 20 bytes (Hex): {raw_data[:20].hex()}")
        print("-" * 30)

if __name__ == "__main__":
    main()