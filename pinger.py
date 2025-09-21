import os
import socket
import asyncio
import subprocess
import re
import ssl
from datetime import datetime

try:
    from aiohttp import ClientSession
except ImportError:
    ClientSession = None

user = os.getenv("USER") or os.getenv("USERNAME")

if os.name == "nt":
    os.system("title \u2800")

def clear_screen():
    if os.name == 'nt':
        os.system('cls')

CUSTOM_COLOR = "\033[38;2;85;0;255m"
CUSTOM_GREY = "\033[38;2;187;187;187m"

def get_hostname(ip, port):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return hostname
    except:
        pass
    if port == 443:
        async def fetch_cert_hostname():
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                reader, writer = await asyncio.open_connection(ip, port, ssl=context)
                cert = writer.get_extra_info('ssl_object').getpeercert()
                writer.close()
                await writer.wait_closed()
                sans = cert.get('subjectAltName', [])
                if sans:
                    return sans[0][1]
            except:
                return "Unknown"
            return "Unknown"
        try:
            return asyncio.run(fetch_cert_hostname())
        except:
            pass
    return "Unknown"

def parse_ping_output(line, ip, port, ping_times=None):
    protocol = "TCP"
    if port in UDP_PORTS:
        protocol = "UDP"
    elif port in HTTP_PORTS:
        protocol = "HTTP" if port == 80 else "HTTPS"
    if "Request timeout" in line or "Destination host unreachable" in line:
        return f"{CUSTOM_COLOR}hostname {CUSTOM_GREY}{get_hostname(ip, port)} " \
               f"{CUSTOM_COLOR}protocol {CUSTOM_GREY}{protocol} " \
               f"{CUSTOM_COLOR}time N/A port {CUSTOM_GREY}{port} bytes N/A status offline"
    ttl_match = re.search(r"[Tt][Tt][Ll]=([0-9]+)", line)
    if not ttl_match:
        ttl_match = re.search(r"ttl[ =]([0-9]+)", line)
    ttl_val = ttl_match.group(1) if ttl_match else "N/A"
    parts = line.split()
    bytes_val = next((p.split('=')[1] for p in parts if "bytes=" in p), "N/A")
    time_val = next((p.split('=')[1] for p in parts if "time=" in p), "N/A")
    status = f"{CUSTOM_GREY}online" if time_val != "N/A" else f"{CUSTOM_GREY}offline"
    return f"{CUSTOM_COLOR}hostname {CUSTOM_GREY}{get_hostname(ip, port)} " \
           f"{CUSTOM_COLOR}protocol {CUSTOM_GREY}{protocol} " \
           f"{CUSTOM_COLOR}ttl {CUSTOM_GREY}{ttl_val} " \
           f"{CUSTOM_COLOR}time {CUSTOM_GREY}{time_val} " \
           f"{CUSTOM_COLOR}port {CUSTOM_GREY}{port} " \
           f"{CUSTOM_COLOR}bytes {CUSTOM_GREY}{bytes_val} " \
           f"{CUSTOM_COLOR}status {status}"

def ip_pinger():
    while True:
        try:
            clear_screen()
            current_time = datetime.now().strftime('%H:%M:%S')
            print(f"{CUSTOM_GREY} made by {CUSTOM_COLOR} https://github.com/skidqs {CUSTOM_GREY}")
            print(f" ")
            print(f"{CUSTOM_GREY} ┌──[{CUSTOM_COLOR}pinger{CUSTOM_GREY}]-[~/{CUSTOM_COLOR}{user}{CUSTOM_GREY}]")
            ip_port = input(f" └───{CUSTOM_COLOR}➤  {CUSTOM_GREY}").strip().split()
            print(f" ")
            if len(ip_port) != 2:
                print(f"{CUSTOM_COLOR}[{CUSTOM_GREY}{current_time}{CUSTOM_COLOR}] {CUSTOM_GREY}invalid input use <ip> <port>")
                continue
            ip_input, port = ip_port
            if not port.isdigit():
                print(f"{CUSTOM_COLOR}[{CUSTOM_GREY}{current_time}{CUSTOM_COLOR}] {CUSTOM_GREY}invalid port")
                continue
            port = int(port)
            ip = None
            domain_input = ip_input
            if domain_input.startswith("http://"):
                domain_input = domain_input[7:]
            elif domain_input.startswith("https://"):
                domain_input = domain_input[8:]
            domain_input = domain_input.split('/')[0]
            try:
                socket.inet_pton(socket.AF_INET, domain_input)
                ip = domain_input
            except OSError:
                try:
                    socket.inet_pton(socket.AF_INET6, domain_input)
                    ip = domain_input
                except OSError:
                    try:
                        ip = socket.gethostbyname(domain_input)
                    except socket.gaierror:
                        print(f"{CUSTOM_COLOR}[{CUSTOM_GREY}{current_time}{CUSTOM_COLOR}] {CUSTOM_GREY}could not resolve domain or ip {CUSTOM_COLOR}{ip_input}{CUSTOM_GREY}")
                        continue
            command = ["ping", "-t", ip] if os.name == "nt" else ["ping", "-i", "0.5", ip]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                output = parse_ping_output(line, ip, port)
                print(output)
        except KeyboardInterrupt:
            print(f"\n{CUSTOM_COLOR}[{CUSTOM_GREY}{current_time}{CUSTOM_COLOR}] {CUSTOM_GREY}ping stopped by user")
            break
        except Exception as e:
            print(f"error {e}")

TCP_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 993, 995, 3306, 3389, 8080, 8443]
UDP_PORTS = [53, 67, 161, 162, 123, 514]
HTTP_PORTS = [80, 443]

async def check_tcp_port(ip, port, session):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except:
        pass
    return None

async def check_udp_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b'', (ip, port))
        sock.close()
        return port
    except:
        pass
    return None

async def check_http_https(ip, port, session):
    try:
        url = f"http://{ip}:{port}"
        async with session.get(url, timeout=1) as response:
            if response.status == 200:
                return port
    except:
        pass
    return None

async def scan_ports(ip, tcp_ports, udp_ports, http_ports):
    if not ClientSession:
        print(f"port scanning disabled")
        return {}
    open_ports = {'tcp': [], 'udp': [], 'http': [], 'https': []}
    async with ClientSession() as session:
        results_tcp = await asyncio.gather(*[check_tcp_port(ip, port, session) for port in tcp_ports])
        open_ports['tcp'] = [p for p in results_tcp if p]
        results_udp = await asyncio.gather(*[check_udp_port(ip, port) for port in udp_ports])
        open_ports['udp'] = [p for p in results_udp if p]
        results_http = await asyncio.gather(*[check_http_https(ip, port, session) for port in http_ports])
        for port in results_http:
            if port:
                if port == 443:
                    open_ports['https'].append(port)
                else:
                    open_ports['http'].append(port)
    return open_ports

if __name__ == "__main__":
    ip_pinger()
