import socket
from scapy.all import IP, TCP, UDP, sr1, ICMP
from concurrent.futures import ThreadPoolExecutor

def tcp_connect_scan(target, port):
    """TCP 연결 스캔"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[TCP Connect] Port {port} is open")
                return port
    except Exception as e:
        print(f"[TCP Connect] Error on port {port}: {e}")
    return None

def syn_scan(target, port):
    """SYN 스캔"""
    try:
        packet = IP(dst=target) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP):
            if response[TCP].flags == "SA":
                print(f"[SYN Scan] Port {port} is open")
                return port
    except Exception as e:
        print(f"[SYN Scan] Error on port {port}: {e}")
    return None

def udp_scan(target, port):
    """UDP 스캔"""
    try:
        packet = IP(dst=target) / UDP(dport=port)
        response = sr1(packet, timeout=1, verbose=0)
        if not response:
            print(f"[UDP Scan] Port {port} is open or filtered")
            return port
        elif response.haslayer(ICMP) and response[ICMP].type == 3:
            print(f"[UDP Scan] Port {port} is closed")
    except Exception as e:
        print(f"[UDP Scan] Error on port {port}: {e}")
    return None

def scan_ports(target, start_port, end_port, scan_type):
    """스캔 메인 함수"""
    print(f"Starting {scan_type} on {target} (Ports {start_port}-{end_port})")
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        for port in range(start_port, end_port + 1):
            if scan_type == "TCP Connect":
                future = executor.submit(tcp_connect_scan, target, port)
            elif scan_type == "SYN":
                future = executor.submit(syn_scan, target, port)
            elif scan_type == "UDP":
                future = executor.submit(udp_scan, target, port)
            try:
                if future.result():  # 열린 포트를 결과에서 확인
                    open_ports.append(port)
            except Exception as e:
                print(f"[-] Error scanning port {port}: {e}")
    
    # 스캔 결과 출력
    if open_ports:
        print("\n[+] Open Ports:")
        for port in open_ports:
            print(f"    - Port {port}")
    else:
        print("\n[-] No open ports found.")

if __name__ == "__main__":
    print("Advanced Port Scanner with Multiple Scan Types")
    target_ip = input("Enter target IP: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    print("Choose scan type: 1. TCP Connect  2. SYN Scan  3. UDP Scan")
    scan_choice = input("Enter your choice: ")

    if scan_choice == "1":
        scan_ports(target_ip, start_port, end_port, "TCP Connect")
    elif scan_choice == "2":
        scan_ports(target_ip, start_port, end_port, "SYN")
    elif scan_choice == "3":
        scan_ports(target_ip, start_port, end_port, "UDP")
    else:
        print("Invalid choice. Exiting.")
