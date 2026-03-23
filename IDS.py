import sys
import os
import time
import json
import socket
import threading
import queue
import hashlib
import struct
import platform
import subprocess
import datetime
import sqlite3
from collections import defaultdict
from colorama import init, Fore

init(autoreset=True)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

class Config:
    def __init__(self, config_file="config.json"):
        self.config_file = config_file
        self.config = self.load()
    
    def load(self):
        default = {
            "port_scan_threshold": 100,
            "syn_flood_threshold": 500,
            "udp_flood_threshold": 500,
            "icmp_flood_threshold": 200,
            "time_window": 10,
            "whitelist": ["127.0.0.1"],
            "auto_block": False,
            "db_file": "ids.db",
            "log_file": "ids.log"
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    default.update(data)
            except:
                pass
        else:
            self.save(default)
        return default
    
    def save(self, config=None):
        if config:
            self.config = config
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def get(self, key, default=None):
        return self.config.get(key, default)
    
    def set(self, key, value):
        self.config[key] = value
        self.save()

class Database:
    def __init__(self, db_file):
        self.db_file = db_file
        self.init()
    
    def init(self):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS alerts
                     (id INTEGER PRIMARY KEY, time TEXT, type TEXT, severity TEXT,
                      src TEXT, dst TEXT, protocol TEXT, port INTEGER, details TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS attacks
                     (id INTEGER PRIMARY KEY, time TEXT, type TEXT, src TEXT,
                      dst TEXT, packets INTEGER)''')
        conn.commit()
        conn.close()
    
    def log_alert(self, alert_type, severity, src, dst, protocol, port, details):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute('''INSERT INTO alerts (time, type, severity, src, dst, protocol, port, details)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (datetime.datetime.now().isoformat(), alert_type, severity,
                   src, dst, protocol, port, details))
        conn.commit()
        conn.close()
    
    def log_attack(self, attack_type, src, dst, packets):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute('''INSERT INTO attacks (time, type, src, dst, packets)
                     VALUES (?, ?, ?, ?, ?)''',
                  (datetime.datetime.now().isoformat(), attack_type, src, dst, packets))
        conn.commit()
        conn.close()
    
    def get_stats(self):
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM alerts")
        alerts = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM attacks")
        attacks = c.fetchone()[0]
        conn.close()
        return {"alerts": alerts, "attacks": attacks}

class PacketCapture:
    def __init__(self, config, db, alert):
        self.config = config
        self.db = db
        self.alert = alert
        self.running = False
        self.sock = None
        
        self.syn = defaultdict(int)
        self.udp = defaultdict(int)
        self.icmp = defaultdict(int)
        self.ports = defaultdict(list)
    
    def start(self):
        self.running = True
        t = threading.Thread(target=self._reset)
        t.daemon = True
        t.start()
        t2 = threading.Thread(target=self._capture)
        t2.daemon = True
        t2.start()
        print("[+] Packet capture started")
    
    def _reset(self):
        while self.running:
            time.sleep(self.config.get("time_window", 10))
            self.syn.clear()
            self.udp.clear()
            self.icmp.clear()
            self.ports.clear()
    
    def _capture(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.sock.bind(('0.0.0.0', 0))
            
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(65535)
                    self._parse(data)
                except:
                    pass
        except PermissionError:
            print("[!] Administrator/root privileges required")
            self.running = False
        except Exception as e:
            print(f"[-] Capture error: {e}")
    
    def _parse(self, data):
        if len(data) < 20:
            return
        
        iph = struct.unpack('!BBHHHBBH4s4s', data[0:20])
        ihl = iph[0] & 0xF
        proto = iph[6]
        src = socket.inet_ntoa(iph[8])
        dst = socket.inet_ntoa(iph[9])
        
        if src in self.config.get("whitelist", []):
            return
        
        ip_len = ihl * 4
        trans = data[ip_len:]
        
        if proto == 6:
            self._tcp(trans, src, dst)
        elif proto == 17:
            self._udp(trans, src, dst)
        elif proto == 1:
            self._icmp(trans, src, dst)
    
    def _tcp(self, data, src, dst):
        if len(data) < 20:
            return
        tcp = struct.unpack('!HHLLBBHHH', data[0:20])
        sport = tcp[0]
        dport = tcp[1]
        flags = tcp[5]
        
        if flags & 0x02:
            self.syn[src] += 1
            threshold = self.config.get("syn_flood_threshold", 500)
            if self.syn[src] > threshold:
                self.alert.trigger("SYN Flood", "CRITICAL", src, dst, "TCP", dport,
                                   f"{self.syn[src]} packets")
                self.db.log_attack("SYN Flood", src, dst, self.syn[src])
                self.syn[src] = 0
        
        key = f"{src}:{dst}"
        now = time.time()
        self.ports[key].append((now, dport))
        window = self.config.get("time_window", 10)
        self.ports[key] = [(t, p) for t, p in self.ports[key] if now - t < window]
        
        unique = len(set(p for _, p in self.ports[key]))
        threshold = self.config.get("port_scan_threshold", 100)
        if unique > threshold:
            self.alert.trigger("Port Scan", "HIGH", src, dst, "TCP", 0,
                               f"{unique} ports in {window}s")
            self.db.log_attack("Port Scan", src, dst, unique)
            self.ports[key].clear()
    
    def _udp(self, data, src, dst):
        if len(data) < 8:
            return
        udp = struct.unpack('!HHHH', data[0:8])
        sport = udp[0]
        dport = udp[1]
        
        self.udp[src] += 1
        threshold = self.config.get("udp_flood_threshold", 500)
        if self.udp[src] > threshold:
            self.alert.trigger("UDP Flood", "CRITICAL", src, dst, "UDP", dport,
                               f"{self.udp[src]} packets")
            self.db.log_attack("UDP Flood", src, dst, self.udp[src])
            self.udp[src] = 0
    
    def _icmp(self, data, src, dst):
        self.icmp[src] += 1
        threshold = self.config.get("icmp_flood_threshold", 200)
        if self.icmp[src] > threshold:
            self.alert.trigger("ICMP Flood", "HIGH", src, dst, "ICMP", 0,
                               f"{self.icmp[src]} packets")
            self.db.log_attack("ICMP Flood", src, dst, self.icmp[src])
            self.icmp[src] = 0
    
    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

class HostMonitor:
    def __init__(self, config, db, alert):
        self.config = config
        self.db = db
        self.alert = alert
        self.running = False
        self.baseline = {}
    
    def start(self):
        self.running = True
        t = threading.Thread(target=self._files)
        t.daemon = True
        t.start()
        if PSUTIL_AVAILABLE:
            t2 = threading.Thread(target=self._processes)
            t2.daemon = True
            t2.start()
        print("[+] Host monitoring started")
    
    def _files(self):
        if platform.system() == "Windows":
            files = [
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "C:\\Windows\\System32\\config\\SAM"
            ]
        else:
            files = [
                "/etc/passwd", "/etc/shadow", "/etc/hosts"
            ]
        
        while self.running:
            for path in files:
                if os.path.exists(path):
                    h = self._hash(path)
                    if path in self.baseline:
                        if self.baseline[path] != h:
                            self.alert.trigger("File Modified", "CRITICAL", "localhost",
                                              "localhost", "FILE", 0, path)
                    self.baseline[path] = h
            time.sleep(60)
    
    def _processes(self):
        susp = ["nc", "netcat", "ncat", "telnet", "mimikatz", "procdump"]
        
        while self.running:
            try:
                for proc in psutil.process_iter(['name', 'cmdline']):
                    try:
                        name = proc.info['name'] or ''
                        cmd = ' '.join(proc.info['cmdline'] or [])
                        for s in susp:
                            if s in name.lower() or s in cmd.lower():
                                self.alert.trigger("Suspicious Process", "HIGH",
                                                  "localhost", "localhost", "PROCESS",
                                                  proc.pid, f"{name}")
                    except:
                        pass
            except:
                pass
            time.sleep(10)
    
    def _hash(self, path):
        try:
            with open(path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None
    
    def stop(self):
        self.running = False

class Alert:
    def __init__(self, config, db):
        self.config = config
        self.db = db
        self.q = queue.Queue()
        t = threading.Thread(target=self._process)
        t.daemon = True
        t.start()
    
    def trigger(self, atype, severity, src, dst, proto, port, details):
        alert = {
            'time': datetime.datetime.now(),
            'type': atype,
            'severity': severity,
            'src': src,
            'dst': dst,
            'proto': proto,
            'port': port,
            'details': details
        }
        self.q.put(alert)
        self.db.log_alert(atype, severity, src, dst, proto, port, details)
    
    def _process(self):
        while True:
            try:
                a = self.q.get(timeout=1)
                self._show(a)
            except:
                pass
    
    def _show(self, a):
        ts = a['time'].strftime("%H:%M:%S")
        if a['severity'] == "CRITICAL":
            color = Fore.RED
        elif a['severity'] == "HIGH":
            color = Fore.YELLOW
        else:
            color = Fore.WHITE
        
        print(f"\n{color}[{ts}] {a['severity']}: {a['type']}")
        print(f"    {a['src']} -> {a['dst']} ({a['proto']}:{a['port']})")
        print(f"    {a['details']}{Fore.RESET}")
        
        if self.config.get("auto_log"):
            with open(self.config.get("log_file", "ids.log"), "a") as f:
                f.write(f"[{ts}] {a['severity']}: {a['type']} - {a['src']} -> {a['dst']} - {a['details']}\n")

class IDS:
    def __init__(self):
        self.config = Config()
        self.db = Database(self.config.get("db_file"))
        self.alert = Alert(self.config, self.db)
        self.packet = PacketCapture(self.config, self.db, self.alert)
        self.host = HostMonitor(self.config, self.db, self.alert)
        self.running = False
    
    def banner(self):
        print("""
╔═══════════════════════════════════════════════════════════════════╗
║                    INTRUSION DETECTION SYSTEM                     ║
║                         Network + Host IDS                        ║
╚═══════════════════════════════════════════════════════════════════╝
        """)
    
    def menu(self):
        stats = self.db.get_stats()
        print(f"""
[ STATUS ] Running: {self.running} | Alerts: {stats['alerts']} | Attacks: {stats['attacks']}

[1] Start IDS
[2] Stop IDS
[3] View Alerts
[4] View Statistics
[5] Configure
[6] Export Report
[7] Exit
        """)
    
    def start(self):
        if self.running:
            print("[!] Already running")
            return
        self.packet.start()
        self.host.start()
        self.running = True
        print("[+] IDS started")
    
    def stop(self):
        if not self.running:
            print("[!] Not running")
            return
        self.packet.stop()
        self.host.stop()
        self.running = False
        print("[!] IDS stopped")
    
    def view_alerts(self):
        conn = sqlite3.connect(self.config.get("db_file"))
        c = conn.cursor()
        c.execute("SELECT time, severity, type, src, dst, details FROM alerts ORDER BY time DESC LIMIT 30")
        rows = c.fetchall()
        conn.close()
        
        if not rows:
            print("[!] No alerts")
            return
        
        print("\n" + "="*80)
        for row in rows:
            print(f"[{row[0]}] {row[1]}: {row[2]}")
            print(f"    {row[3]} -> {row[4]}")
            print(f"    {row[5]}\n")
    
    def view_stats(self):
        conn = sqlite3.connect(self.config.get("db_file"))
        c = conn.cursor()
        
        c.execute("SELECT type, COUNT(*) FROM attacks GROUP BY type")
        attacks = c.fetchall()
        
        c.execute("SELECT src, COUNT(*) FROM attacks GROUP BY src ORDER BY COUNT(*) DESC LIMIT 5")
        sources = c.fetchall()
        
        conn.close()
        
        print("\n" + "="*80)
        print("ATTACK STATISTICS")
        print("="*80)
        
        print("\n[ Attack Types ]")
        for t, cnt in attacks:
            print(f"    {t}: {cnt}")
        
        print("\n[ Top Attack Sources ]")
        for src, cnt in sources:
            print(f"    {src}: {cnt}")
    
    def configure(self):
        print("\n[ Current Configuration ]")
        for k, v in self.config.config.items():
            print(f"    {k}: {v}")
        
        print("\n[ Enter key to modify (or 'save') ]")
        key = input("╰──➤ ").strip()
        
        if key == "save":
            return
        if key in self.config.config:
            val = input(f"New value for {key}: ").strip()
            if isinstance(self.config.config[key], int):
                try:
                    val = int(val)
                except:
                    print("[-] Invalid number")
                    return
            elif isinstance(self.config.config[key], bool):
                val = val.lower() in ['true', 'yes', '1']
            elif isinstance(self.config.config[key], list):
                val = [x.strip() for x in val.split(',')]
            self.config.set(key, val)
            print(f"[+] Updated {key}")
    
    def export(self):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{ts}.txt"
        
        conn = sqlite3.connect(self.config.get("db_file"))
        c = conn.cursor()
        
        with open(filename, 'w') as f:
            f.write("IDS REPORT\n")
            f.write(f"Generated: {datetime.datetime.now()}\n\n")
            
            c.execute("SELECT COUNT(*) FROM alerts")
            f.write(f"Total Alerts: {c.fetchone()[0]}\n")
            
            c.execute("SELECT type, COUNT(*) FROM attacks GROUP BY type")
            f.write("\nAttacks by Type:\n")
            for t, cnt in c.fetchall():
                f.write(f"  {t}: {cnt}\n")
            
            c.execute("SELECT src, COUNT(*) FROM attacks GROUP BY src ORDER BY COUNT(*) DESC LIMIT 10")
            f.write("\nTop Attackers:\n")
            for src, cnt in c.fetchall():
                f.write(f"  {src}: {cnt}\n")
        
        conn.close()
        print(f"[+] Report saved: {filename}")
    
    def run(self):
        while True:
            self.banner()
            self.menu()
            choice = input("╰──➤ ").strip()
            
            if choice == '1':
                self.start()
            elif choice == '2':
                self.stop()
            elif choice == '3':
                self.view_alerts()
            elif choice == '4':
                self.view_stats()
            elif choice == '5':
                self.configure()
            elif choice == '6':
                self.export()
            elif choice == '7':
                self.stop()
                print("[!] Exiting")
                sys.exit(0)
            else:
                print("[-] Invalid option")
            
            input("\n[Enter] ")

if __name__ == "__main__":
    try:
        if platform.system() == "Windows":
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] Administrator privileges required")
                input("Press Enter to exit...")
                sys.exit(1)
        else:
            if os.geteuid() != 0:
                print("[!] Root privileges required")
                input("Press Enter to exit...")
                sys.exit(1)
        
        ids = IDS()
        ids.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error: {e}")
        input("Press Enter to exit...")
        sys.exit(1)