import tkinter as tk
from tkinter import ttk, messagebox
import socket
import struct
import datetime
import os
import sys
import threading
import time

# --- CONFIGURAÇÕES GERAIS ---
# Define a interface de rede virtual criada pelo túnel
INTERFACE = "tun0"
LOG_DIR = "."

# Nomes dos arquivos onde os logs serão salvos (Requisito do PDF)
FILE_INTERNET = "camada_internet.csv"
FILE_TRANSPORTE = "camada_transporte.csv"
FILE_APLICACAO = "camada_aplicacao.csv"

# --- PALETA DE CORES (TEMA DRACULA) ---
# Usada para dar um visual profissional e "hacker" para a ferramenta
# Referência: Paleta oficial Dracula Theme
DRACULA_BG       = "#282a36"  # Fundo principal (Escuro)
DRACULA_CURRENT  = "#44475a"  # Linha atual/Seleção (Cinza azulado)
DRACULA_FG       = "#f8f8f2"  # Texto principal (Branco gelo)
DRACULA_COMMENT  = "#6272a4"  # Comentários/Cinza
DRACULA_CYAN     = "#8be9fd"  # Ciano
DRACULA_GREEN    = "#50fa7b"  # Verde
DRACULA_ORANGE   = "#ffb86c"  # Laranja
DRACULA_PINK     = "#ff79c6"  # Rosa
DRACULA_PURPLE   = "#bd93f9"  # Roxo
DRACULA_RED      = "#ff5555"  # Vermelho (Erros/Botões de parada)
DRACULA_YELLOW   = "#f1fa8c"  # Amarelo

# Configuração de Fontes para manter a legibilidade
FONT_UI       = ("Segoe UI", 10)
FONT_BOLD     = ("Segoe UI", 10, "bold")
FONT_NUMBERS  = ("Consolas", 13, "bold") # Fonte monoespaçada para números
FONT_HEADER   = ("Consolas", 18, "bold")

class NetworkMonitorApp:
    """
    Classe principal da aplicação gráfica.
    Gerencia a Interface (UI), a captura de pacotes (Sniffer) e os Logs.
    """
    def __init__(self, root):
        self.root = root
        self.root.title(f"🧛 DRACULA MONITOR // {INTERFACE}")
        self.root.geometry("980x720")
        self.root.configure(bg=DRACULA_BG)
        
        # Variável de controle para parar a thread do sniffer ao fechar o app
        self.running = True
        
        # Dicionário de Estatísticas (Memória Compartilhada)
        # Armazena contadores em tempo real para evitar leituras de disco constantes
        self.stats = {
            "total_pacotes": 0,
            "IPv4": 0, "IPv6": 0, "ICMP": 0,
            "TCP": 0, "UDP": 0,
            "HTTP": 0, "DNS": 0, "DHCP": 0, "NTP": 0,
            "clientes": {} # Armazena IP e Volume de dados dos clientes do túnel
        }

        # Inicialização dos subsistemas
        self.init_logs()     # Cria arquivos CSV se não existirem
        self.setup_styles()  # Configura o tema visual (cores/fontes)
        self.setup_ui()      # Desenha os elementos na tela
        
        # Inicia a Thread do Sniffer (Paralelismo)
        # 'daemon=True' garante que a thread morra se o programa principal fechar
        self.sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)
        self.sniff_thread.start()

        # Inicia o loop de atualização da interface gráfica
        self.update_ui_loop()

    def init_logs(self):
        """
        Verifica se os arquivos de log existem. Se não, cria-os com o cabeçalho correto.
        Isso atende aos requisitos de colunas específicas do PDF.
        """
        headers = {
            FILE_INTERNET: "Data_Hora,Protocolo,IP_Origem,IP_Destino,ID_Proto_Carga,Info_Extra,Tamanho_Total\n",
            FILE_TRANSPORTE: "Data_Hora,Protocolo,IP_Origem,Porta_Origem,IP_Destino,Porta_Destino,Tamanho_Total\n",
            FILE_APLICACAO: "Data_Hora,Protocolo,Informacoes\n"
        }
        for f, h in headers.items():
            if not os.path.exists(f):
                try: open(f, 'w').write(h)
                except: pass

    def log_csv(self, filename, data_list):
        """
        Escreve uma linha no arquivo CSV especificado.
        Converte a lista de dados em uma string separada por vírgulas.
        """
        try:
            with open(filename, 'a') as f:
                f.write(",".join([str(x) for x in data_list]) + "\n")
        except: pass

    def setup_styles(self):
        """
        Configura o estilo 'Dark Mode' usando o tema 'clam' do Tkinter como base
        e sobrescrevendo as cores com a paleta Dracula.
        """
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configuração global de cores de fundo e texto
        style.configure(".", background=DRACULA_BG, foreground=DRACULA_FG, font=FONT_UI)
        style.configure("TLabel", background=DRACULA_BG, foreground=DRACULA_FG)
        style.configure("TFrame", background=DRACULA_BG)
        
        # Estilo dos "Cards" (Caixas de agrupamento de estatísticas)
        style.configure("Card.TLabelframe", background=DRACULA_CURRENT, relief="flat", borderwidth=0)
        style.configure("Card.TLabelframe.Label", background=DRACULA_CURRENT, foreground=DRACULA_PURPLE, font=FONT_BOLD)

        # Estilo da Tabela (Treeview) - Customização para fundo escuro
        style.configure("Treeview", 
                        background=DRACULA_BG, 
                        foreground=DRACULA_FG, 
                        fieldbackground=DRACULA_BG,
                        borderwidth=0,
                        rowheight=28,
                        font=("Consolas", 10))
        
        # Cabeçalho da tabela
        style.configure("Treeview.Heading", 
                        background=DRACULA_CURRENT, 
                        foreground=DRACULA_PINK, 
                        font=FONT_BOLD,
                        relief="flat")
        
        # Cor de seleção da tabela
        style.map("Treeview", 
                  background=[('selected', DRACULA_COMMENT)], 
                  foreground=[('selected', DRACULA_FG)])

    def setup_ui(self):
        """Constrói a interface gráfica: Header, Cards de Stats e Tabela."""
        
        # --- HEADER (Topo) ---
        top_frame = tk.Frame(self.root, bg=DRACULA_BG)
        top_frame.pack(fill="x", padx=30, pady=25)
        
        # Ícone e Título
        lbl_icon = tk.Label(top_frame, text="🧛🏼‍♂️", bg=DRACULA_BG, fg=DRACULA_YELLOW, font=("Segoe UI Emoji", 24))
        lbl_icon.pack(side="left", padx=(0,10))
        
        title_cont = tk.Frame(top_frame, bg=DRACULA_BG)
        title_cont.pack(side="left")
        
        lbl_title = tk.Label(title_cont, text="NETWORK SNIFFER", bg=DRACULA_BG, fg=DRACULA_PURPLE, font=FONT_HEADER)
        lbl_title.pack(anchor="w")
        
        lbl_sub = tk.Label(title_cont, text=f"INTERFACE: {INTERFACE} | RAW SOCKET", bg=DRACULA_BG, fg=DRACULA_COMMENT, font=("Consolas", 10))
        lbl_sub.pack(anchor="w")
        
        # Contador Total de Pacotes (Destaque em Verde)
        self.lbl_total = tk.Label(top_frame, text="0 PKTS", bg=DRACULA_BG, fg=DRACULA_GREEN, font=("Consolas", 32, "bold"))
        self.lbl_total.pack(side="right")

        # --- GRID DE CARDS (Meio) ---
        grid_frame = tk.Frame(self.root, bg=DRACULA_BG)
        grid_frame.pack(fill="x", padx=25, pady=10)

        # Função auxiliar para criar linhas de dados dentro dos cards
        def create_stat_row(parent, label, var_name, value_color):
            frame = tk.Frame(parent, bg=DRACULA_CURRENT)
            frame.pack(fill="x", pady=3, padx=15)
            
            lbl = tk.Label(frame, text=label, bg=DRACULA_CURRENT, fg=DRACULA_CYAN, width=15, anchor="w", font=("Consolas", 10))
            lbl.pack(side="left")
            
            # Cria um Label para o valor e salva uma referência nele (self.var_name)
            # para poder atualizar o texto depois no update_ui_loop
            val = tk.Label(frame, text="0", bg=DRACULA_CURRENT, fg=value_color, font=FONT_NUMBERS)
            val.pack(side="right")
            setattr(self, var_name, val)

        # Card 1: Camada de Rede (L3)
        frm_net = ttk.LabelFrame(grid_frame, text=" NETWORK LAYER ", style="Card.TLabelframe")
        frm_net.grid(row=0, column=0, padx=8, sticky="nsew", ipady=10)
        create_stat_row(frm_net, "IPv4", "lbl_ipv4", DRACULA_FG)
        create_stat_row(frm_net, "IPv6", "lbl_ipv6", DRACULA_COMMENT)
        create_stat_row(frm_net, "ICMP", "lbl_icmp", DRACULA_ORANGE)

        # Card 2: Camada de Transporte (L4)
        frm_trans = ttk.LabelFrame(grid_frame, text=" TRANSPORT LAYER ", style="Card.TLabelframe")
        frm_trans.grid(row=0, column=1, padx=8, sticky="nsew", ipady=10)
        create_stat_row(frm_trans, "TCP Segments", "lbl_tcp", DRACULA_PINK)
        create_stat_row(frm_trans, "UDP Datagrams", "lbl_udp", DRACULA_PINK)
        
        # Card 3: Camada de Aplicação (L7)
        frm_app = ttk.LabelFrame(grid_frame, text=" APPLICATION LAYER ", style="Card.TLabelframe")
        frm_app.grid(row=0, column=2, padx=8, sticky="nsew", ipady=10)
        create_stat_row(frm_app, "HTTP / Web", "lbl_http", DRACULA_PURPLE)
        create_stat_row(frm_app, "DNS Queries", "lbl_dns", DRACULA_PURPLE)
        create_stat_row(frm_app, "DHCP / NTP", "lbl_dhcp_ntp", DRACULA_FG)

        # Configura o grid para expandir igualmente
        grid_frame.columnconfigure(0, weight=1)
        grid_frame.columnconfigure(1, weight=1)
        grid_frame.columnconfigure(2, weight=1)

        # --- TABELA DE CLIENTES (Base) ---
        lbl_table = tk.Label(self.root, text=">> TUNNEL CLIENTS ACTIVITY", bg=DRACULA_BG, fg=DRACULA_YELLOW, font=("Consolas", 12, "bold"))
        lbl_table.pack(pady=(30, 5), anchor="w", padx=30)

        # Container da tabela
        table_container = tk.Frame(self.root, bg=DRACULA_COMMENT, bd=1)
        table_container.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        # Configuração das colunas da tabela
        cols = ("ip", "vol", "seen")
        self.tree = ttk.Treeview(table_container, columns=cols, show="headings", height=8)
        
        self.tree.heading("ip", text="IP ADDRESS")
        self.tree.heading("vol", text="DATA VOLUME (BYTES)")
        self.tree.heading("seen", text="LAST SEEN")
        
        self.tree.column("ip", anchor="center", width=200)
        self.tree.column("vol", anchor="center", width=150)
        self.tree.column("seen", anchor="center", width=250)
        
        self.tree.pack(fill="both", expand=True)

        # Botão de Parar
        btn_quit = tk.Button(self.root, text="STOP SNIFFING", bg=DRACULA_RED, fg=DRACULA_BG, 
                             font=("Consolas", 11, "bold"), command=self.on_close, 
                             relief="flat", activebackground=DRACULA_ORANGE, cursor="hand2")
        btn_quit.pack(pady=(0, 25), ipadx=30, ipady=5)

    def update_ui_loop(self):
        """
        Loop da Thread Principal (GUI).
        Atualiza os valores na tela a cada 500ms lendo o dicionário self.stats.
        Isso desacopla a captura (rápida) da visualização (lenta).
        """
        if not self.running: return

        # Atualiza Labels de Texto com os valores atuais do dicionário stats
        self.lbl_total.config(text=f"{self.stats['total_pacotes']}")
        self.lbl_ipv4.config(text=str(self.stats['IPv4']))
        self.lbl_ipv6.config(text=str(self.stats['IPv6']))
        self.lbl_icmp.config(text=str(self.stats['ICMP']))
        self.lbl_tcp.config(text=str(self.stats['TCP']))
        self.lbl_udp.config(text=str(self.stats['UDP']))
        self.lbl_http.config(text=str(self.stats['HTTP']))
        self.lbl_dns.config(text=str(self.stats['DNS']))
        self.lbl_dhcp_ntp.config(text=f"{self.stats['DHCP']} / {self.stats['NTP']}")

        # Atualiza Tabela de Clientes
        # 1. Salva seleção atual
        selected = self.tree.selection()
        # 2. Limpa tabela
        self.tree.delete(*self.tree.get_children())
        
        # 3. Ordena clientes por volume de dados (Decrescente)
        sorted_clients = sorted(self.stats['clientes'].items(), key=lambda x: x[1]['bytes'], reverse=True)

        # 4. Reinsere dados atualizados
        for ip, data in sorted_clients:
            # Formata bytes com separador de milhar
            vol_str = f"{data['bytes']:,}".replace(",", ".")
            self.tree.insert("", "end", iid=ip, values=(ip, vol_str, data['last_seen']))
            
        # 5. Restaura seleção
        if selected and self.tree.exists(selected[0]):
            self.tree.selection_set(selected)

        # Reagendar próxima execução em 500ms
        self.root.after(500, self.update_ui_loop)

    def start_sniffing(self):
        """
        Lógica da Thread Secundária (Sniffer).
        Cria o Raw Socket e entra num loop infinito de leitura.
        """
        try:
            # AF_PACKET e SOCK_RAW: Permite acesso direto à camada de rede (L2/L3)
            # ntohs(0x0003): ETH_P_ALL (Captura todos os protocolos)
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            # Bind na interface do túnel (tun0)
            s.bind((INTERFACE, 0))
        except:
            # Se falhar (geralmente falta de sudo), avisa e fecha
            self.root.after(0, lambda: messagebox.showerror("ROOT ERROR", "Please run with SUDO!"))
            self.root.destroy()
            return

        while self.running:
            try:
                # Lê até 65535 bytes (Tamanho máximo de um pacote IP)
                raw_data, _ = s.recvfrom(65535)
                # Envia para processamento
                self.process_packet(raw_data)
            except: pass

    def process_packet(self, raw_data):
        """
        Analisa o pacote binário recebido e extrai informações das camadas.
        """
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        pkt_len = len(raw_data)
        self.stats['total_pacotes'] += 1

        if pkt_len < 20: return # Pacote inválido (muito pequeno)
        
        # --- CAMADA DE REDE (IP) ---
        # O primeiro byte contém Versão (4 bits) e Tamanho do Cabeçalho (4 bits)
        version = raw_data[0] >> 4
        ihl = raw_data[0] & 0xF
        iph_len = ihl * 4  # Tamanho em bytes (palavras de 32 bits * 4)

        if version == 4:
            self.stats['IPv4'] += 1
            try:
                # Desempacota cabeçalho IPv4 (20 bytes)
                # ! = Network Endian, B = Byte, H = Short, 4s = 4 bytes string (IP)
                ttl, proto, src, dst = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
                src_ip = socket.inet_ntoa(src)
                dst_ip = socket.inet_ntoa(dst)
            except: return

            # Identificação de Clientes do Túnel (Faixa 172.31.x.x)
            if src_ip.startswith("172.31."):
                if src_ip not in self.stats['clientes']:
                    self.stats['clientes'][src_ip] = {'bytes': 0, 'last_seen': ''}
                self.stats['clientes'][src_ip]['bytes'] += pkt_len
                self.stats['clientes'][src_ip]['last_seen'] = timestamp

            # Mapeamento de Protocolo L4
            p_name = {1:"ICMP", 6:"TCP", 17:"UDP"}.get(proto, "OTHER")
            extra = "-"
            
            # Tratamento especial para ICMP (Ping)
            if proto == 1: 
                self.stats['ICMP'] += 1
                if len(raw_data) >= iph_len + 2:
                    t, c = struct.unpack('!BB', raw_data[iph_len:iph_len+2])
                    extra = f"Type:{t} Code:{c}"

            # LOG L3
            self.log_csv(FILE_INTERNET, [timestamp, f"IPv4({p_name})", src_ip, dst_ip, proto, extra, pkt_len])

            # --- CAMADA DE TRANSPORTE (L4) ---
            if proto in [6, 17]: # TCP ou UDP
                trans_data = raw_data[iph_len:]
                if len(trans_data) < 4: return # Precisa de pelo menos portas origem/destino

                sport, dport = struct.unpack('!HH', trans_data[:4])
                
                if proto == 6: self.stats['TCP'] += 1
                else: self.stats['UDP'] += 1
                
                # LOG L4
                self.log_csv(FILE_TRANSPORTE, [timestamp, p_name, src_ip, sport, dst_ip, dport, pkt_len])

                # Cálculo do tamanho do cabeçalho de transporte para achar o Payload
                hlen_trans = 8 # UDP fixo
                if proto == 6: # TCP variável
                    if len(trans_data) < 20: return
                    # Data Offset está no byte 12, 4 bits superiores
                    hlen_trans = (trans_data[12] >> 4) * 4
                
                # --- CAMADA DE APLICAÇÃO (L7) ---
                if len(trans_data) > hlen_trans:
                    self.parse_app(trans_data[hlen_trans:], sport, dport, timestamp)

        elif version == 6:
            self.stats['IPv6'] += 1
            self.log_csv(FILE_INTERNET, [timestamp, "IPv6", "-", "-", "-", "-", pkt_len])

    def parse_app(self, data, sp, dp, ts):
        """
        Tenta identificar o protocolo de aplicação baseado nas portas.
        Extrai informações básicas do payload.
        """
        ports = [sp, dp]
        app = None
        info = ""

        # Identificação por portas padrão
        if 80 in ports or 8080 in ports:
            app = "HTTP"; self.stats['HTTP'] += 1
            try: info = data[:40].decode('utf-8').split('\r\n')[0] # Tenta ler GET/POST
            except: info = "Payload Binário"
        elif 53 in ports:
            app = "DNS"; self.stats['DNS'] += 1; info = "Query DNS"
        elif 67 in ports or 68 in ports:
            app = "DHCP"; self.stats['DHCP'] += 1; info = "Discovery/Offer"
        elif 123 in ports:
            app = "NTP"; self.stats['NTP'] += 1; info = "Sync Time"

        if app:
            # LOG L7
            self.log_csv(FILE_APLICACAO, [ts, app, f'"{info}"'])

    def on_close(self):
        """Encerra o programa de forma segura, parando threads."""
        self.running = False
        self.root.destroy()
        sys.exit(0)

if __name__ == "__main__":
    # Inicializa o Tkinter
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    # Configura o evento de fechar janela (X) para chamar nossa função de limpeza
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    # Inicia o loop principal da interface
    root.mainloop()