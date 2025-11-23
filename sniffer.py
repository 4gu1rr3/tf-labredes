import tkinter as tk
from tkinter import ttk, messagebox
import socket
import struct
import datetime
import os
import sys
import threading
import time

# --- CONFIGURAÇÕES ---
INTERFACE = "tun0"
LOG_DIR = "."

FILE_INTERNET = "camada_internet.csv"
FILE_TRANSPORTE = "camada_transporte.csv"
FILE_APLICACAO = "camada_aplicacao.csv"

# --- PALETA DRACULA OFICIAL ---
# Referência: https://draculatheme.com/contribute
DRACULA_BG       = "#282a36"  # Background
DRACULA_CURRENT  = "#44475a"  # Current Line / Selection / Panels
DRACULA_FG       = "#f8f8f2"  # Foreground
DRACULA_COMMENT  = "#6272a4"  # Comment
DRACULA_CYAN     = "#8be9fd"  # Cyan
DRACULA_GREEN    = "#50fa7b"  # Green
DRACULA_ORANGE   = "#ffb86c"  # Orange
DRACULA_PINK     = "#ff79c6"  # Pink
DRACULA_PURPLE   = "#bd93f9"  # Purple
DRACULA_RED      = "#ff5555"  # Red
DRACULA_YELLOW   = "#f1fa8c"  # Yellow

# Fontes
FONT_UI       = ("Segoe UI", 10)
FONT_BOLD     = ("Segoe UI", 10, "bold")
FONT_NUMBERS  = ("Consolas", 13, "bold")
FONT_HEADER   = ("Consolas", 18, "bold")

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"🧛 DRACULA MONITOR // {INTERFACE}")
        self.root.geometry("980x720")
        self.root.configure(bg=DRACULA_BG)
        
        # Estado
        self.running = True
        
        # Estatísticas
        self.stats = {
            "total_pacotes": 0,
            "IPv4": 0, "IPv6": 0, "ICMP": 0,
            "TCP": 0, "UDP": 0,
            "HTTP": 0, "DNS": 0, "DHCP": 0, "NTP": 0,
            "clientes": {} 
        }

        self.init_logs()
        self.setup_styles()
        self.setup_ui()
        
        # Thread Sniffer
        self.sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)
        self.sniff_thread.start()

        # Loop UI
        self.update_ui_loop()

    def init_logs(self):
        """Cria headers dos CSVs."""
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
        try:
            with open(filename, 'a') as f:
                f.write(",".join([str(x) for x in data_list]) + "\n")
        except: pass

    def setup_styles(self):
        """Configura o visual Dracula."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Cores globais do Tkinter
        style.configure(".", background=DRACULA_BG, foreground=DRACULA_FG, font=FONT_UI)
        style.configure("TLabel", background=DRACULA_BG, foreground=DRACULA_FG)
        style.configure("TFrame", background=DRACULA_BG)
        
        # Estilo dos Cards (Group Boxes) -> Usando DRACULA_CURRENT para destaque
        style.configure("Card.TLabelframe", background=DRACULA_CURRENT, relief="flat", borderwidth=0)
        style.configure("Card.TLabelframe.Label", background=DRACULA_CURRENT, foreground=DRACULA_PURPLE, font=FONT_BOLD)

        # Labels dentro dos Cards precisam ter o fundo do card
        style.configure("CardLabel.TLabel", background=DRACULA_CURRENT, foreground=DRACULA_FG)

        # Treeview (Tabela)
        style.configure("Treeview", 
                        background=DRACULA_BG, 
                        foreground=DRACULA_FG, 
                        fieldbackground=DRACULA_BG,
                        borderwidth=0,
                        rowheight=28,
                        font=("Consolas", 10))
        
        style.configure("Treeview.Heading", 
                        background=DRACULA_CURRENT, 
                        foreground=DRACULA_PINK, 
                        font=FONT_BOLD,
                        relief="flat")
        
        # Mapa de cores para seleção (Roxo Dracula)
        style.map("Treeview", 
                  background=[('selected', DRACULA_COMMENT)], 
                  foreground=[('selected', DRACULA_FG)])

    def setup_ui(self):
        # --- HEADER ---
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
        
        # Contador Total
        self.lbl_total = tk.Label(top_frame, text="0 PKTS", bg=DRACULA_BG, fg=DRACULA_GREEN, font=("Consolas", 32, "bold"))
        self.lbl_total.pack(side="right")

        # --- GRID DE CARDS ---
        grid_frame = tk.Frame(self.root, bg=DRACULA_BG)
        grid_frame.pack(fill="x", padx=25, pady=10)

        # Helper para criar linhas internas dos cards
        def create_stat_row(parent, label, var_name, value_color):
            frame = tk.Frame(parent, bg=DRACULA_CURRENT)
            frame.pack(fill="x", pady=3, padx=15)
            
            lbl = tk.Label(frame, text=label, bg=DRACULA_CURRENT, fg=DRACULA_CYAN, width=15, anchor="w", font=("Consolas", 10))
            lbl.pack(side="left")
            
            val = tk.Label(frame, text="0", bg=DRACULA_CURRENT, fg=value_color, font=FONT_NUMBERS)
            val.pack(side="right")
            
            setattr(self, var_name, val)

        # Card 1: Network Layer
        frm_net = ttk.LabelFrame(grid_frame, text=" NETWORK LAYER ", style="Card.TLabelframe")
        frm_net.grid(row=0, column=0, padx=8, sticky="nsew", ipady=10)
        create_stat_row(frm_net, "IPv4", "lbl_ipv4", DRACULA_FG)
        create_stat_row(frm_net, "IPv6", "lbl_ipv6", DRACULA_COMMENT)
        create_stat_row(frm_net, "ICMP", "lbl_icmp", DRACULA_ORANGE)

        # Card 2: Transport Layer
        frm_trans = ttk.LabelFrame(grid_frame, text=" TRANSPORT LAYER ", style="Card.TLabelframe")
        frm_trans.grid(row=0, column=1, padx=8, sticky="nsew", ipady=10)
        create_stat_row(frm_trans, "TCP Segments", "lbl_tcp", DRACULA_PINK)
        create_stat_row(frm_trans, "UDP Datagrams", "lbl_udp", DRACULA_PINK)
        
        # Card 3: Application Layer
        frm_app = ttk.LabelFrame(grid_frame, text=" APPLICATION LAYER ", style="Card.TLabelframe")
        frm_app.grid(row=0, column=2, padx=8, sticky="nsew", ipady=10)
        create_stat_row(frm_app, "HTTP / Web", "lbl_http", DRACULA_PURPLE)
        create_stat_row(frm_app, "DNS Queries", "lbl_dns", DRACULA_PURPLE)
        create_stat_row(frm_app, "DHCP / NTP", "lbl_dhcp_ntp", DRACULA_FG)

        grid_frame.columnconfigure(0, weight=1)
        grid_frame.columnconfigure(1, weight=1)
        grid_frame.columnconfigure(2, weight=1)

        # --- TABELA DE CLIENTES ---
        lbl_table = tk.Label(self.root, text=">> TUNNEL CLIENTS ACTIVITY", bg=DRACULA_BG, fg=DRACULA_YELLOW, font=("Consolas", 12, "bold"))
        lbl_table.pack(pady=(30, 5), anchor="w", padx=30)

        # Container da tabela (para dar uma borda sutil)
        table_container = tk.Frame(self.root, bg=DRACULA_COMMENT, bd=1)
        table_container.pack(fill="both", expand=True, padx=30, pady=(0, 20))

        cols = ("ip", "vol", "seen")
        self.tree = ttk.Treeview(table_container, columns=cols, show="headings", height=8)
        
        self.tree.heading("ip", text="IP ADDRESS")
        self.tree.heading("vol", text="DATA VOLUME (BYTES)")
        self.tree.heading("seen", text="LAST SEEN")
        
        self.tree.column("ip", anchor="center", width=200)
        self.tree.column("vol", anchor="center", width=150)
        self.tree.column("seen", anchor="center", width=250)
        
        self.tree.pack(fill="both", expand=True)

        # Botão Exit
        btn_quit = tk.Button(self.root, text="STOP SNIFFING", bg=DRACULA_RED, fg=DRACULA_BG, 
                             font=("Consolas", 11, "bold"), command=self.on_close, 
                             relief="flat", activebackground=DRACULA_ORANGE, cursor="hand2")
        btn_quit.pack(pady=(0, 25), ipadx=30, ipady=5)

    def update_ui_loop(self):
        if not self.running: return

        # Atualiza Labels
        self.lbl_total.config(text=f"{self.stats['total_pacotes']}")
        self.lbl_ipv4.config(text=str(self.stats['IPv4']))
        self.lbl_ipv6.config(text=str(self.stats['IPv6']))
        self.lbl_icmp.config(text=str(self.stats['ICMP']))
        self.lbl_tcp.config(text=str(self.stats['TCP']))
        self.lbl_udp.config(text=str(self.stats['UDP']))
        self.lbl_http.config(text=str(self.stats['HTTP']))
        self.lbl_dns.config(text=str(self.stats['DNS']))
        self.lbl_dhcp_ntp.config(text=f"{self.stats['DHCP']} / {self.stats['NTP']}")

        # Atualiza Tabela
        selected = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        
        sorted_clients = sorted(self.stats['clientes'].items(), key=lambda x: x[1]['bytes'], reverse=True)

        for ip, data in sorted_clients:
            vol_str = f"{data['bytes']:,}".replace(",", ".")
            self.tree.insert("", "end", iid=ip, values=(ip, vol_str, data['last_seen']))
            
        if selected and self.tree.exists(selected[0]):
            self.tree.selection_set(selected)

        self.root.after(500, self.update_ui_loop)

    def start_sniffing(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            s.bind((INTERFACE, 0))
        except:
            self.root.after(0, lambda: messagebox.showerror("ROOT ERROR", "Please run with SUDO!"))
            self.root.destroy()
            return

        while self.running:
            try:
                raw_data, _ = s.recvfrom(65535)
                self.process_packet(raw_data)
            except: pass

    def process_packet(self, raw_data):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        pkt_len = len(raw_data)
        self.stats['total_pacotes'] += 1

        if pkt_len < 20: return
        
        version = raw_data[0] >> 4
        ihl = raw_data[0] & 0xF
        iph_len = ihl * 4

        if version == 4:
            self.stats['IPv4'] += 1
            try:
                ttl, proto, src, dst = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
                src_ip = socket.inet_ntoa(src)
                dst_ip = socket.inet_ntoa(dst)
            except: return

            if src_ip.startswith("172.31."):
                if src_ip not in self.stats['clientes']:
                    self.stats['clientes'][src_ip] = {'bytes': 0, 'last_seen': ''}
                self.stats['clientes'][src_ip]['bytes'] += pkt_len
                self.stats['clientes'][src_ip]['last_seen'] = timestamp

            p_name = {1:"ICMP", 6:"TCP", 17:"UDP"}.get(proto, "OTHER")
            extra = "-"
            
            if proto == 1: 
                self.stats['ICMP'] += 1
                if len(raw_data) >= iph_len + 2:
                    t, c = struct.unpack('!BB', raw_data[iph_len:iph_len+2])
                    extra = f"Type:{t} Code:{c}"

            self.log_csv(FILE_INTERNET, [timestamp, f"IPv4({p_name})", src_ip, dst_ip, proto, extra, pkt_len])

            if proto in [6, 17]:
                trans_data = raw_data[iph_len:]
                if len(trans_data) < 4: return

                sport, dport = struct.unpack('!HH', trans_data[:4])
                
                if proto == 6: self.stats['TCP'] += 1
                else: self.stats['UDP'] += 1
                
                self.log_csv(FILE_TRANSPORTE, [timestamp, p_name, src_ip, sport, dst_ip, dport, pkt_len])

                hlen_trans = 8
                if proto == 6:
                    if len(trans_data) < 20: return
                    hlen_trans = (trans_data[12] >> 4) * 4
                
                if len(trans_data) > hlen_trans:
                    self.parse_app(trans_data[hlen_trans:], sport, dport, timestamp)

        elif version == 6:
            self.stats['IPv6'] += 1
            self.log_csv(FILE_INTERNET, [timestamp, "IPv6", "-", "-", "-", "-", pkt_len])

    def parse_app(self, data, sp, dp, ts):
        ports = [sp, dp]
        app = None
        info = ""

        if 80 in ports or 8080 in ports:
            app = "HTTP"; self.stats['HTTP'] += 1
            try: info = data[:40].decode('utf-8').split('\r\n')[0]
            except: info = "Payload"
        elif 53 in ports:
            app = "DNS"; self.stats['DNS'] += 1; info = "Query"
        elif 67 in ports or 68 in ports:
            app = "DHCP"; self.stats['DHCP'] += 1; info = "Discovery"
        elif 123 in ports:
            app = "NTP"; self.stats['NTP'] += 1; info = "Sync"

        if app:
            self.log_csv(FILE_APLICACAO, [ts, app, f'"{info}"'])

    def on_close(self):
        self.running = False
        self.root.destroy()
        sys.exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
