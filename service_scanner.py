import socket
from scapy.all import IP, TCP, UDP, sr1, ICMP
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional
from .service_detector import ServiceDetector

class ServiceScanner: 
    def __init__(self, timeout: int = 2):
        self.timeout = timeout
        self.service_detector = ServiceDetector(timeout=timeout)
   
    def tcp_connect_scan(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """TCP 연결 스캔 + 서비스 탐지"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    print(f"[TCP Connect] Port {port} is open")
                    # 서비스 탐지 추가
                    service_info = self.service_detector.get_service_info(target, port)
                    return {
                        'port': port,
                        'status': 'open',
                        'scan_type': 'TCP Connect',
                        **service_info
                    }
        except Exception as e:
            print(f"[TCP Connect] Error on port {port}: {e}")
        return None

    def syn_scan(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """SYN 스캔 + 서비스 탐지"""
        try:
            packet = IP(dst=target) / TCP(dport=port, flags="S")
            response = sr1(packet, timeout=self.timeout, verbose=0)
            if response and response.haslayer(TCP):
                if response[TCP].flags == "SA":
                    print(f"[SYN Scan] Port {port} is open")
                    # 서비스 탐지 추가
                    service_info = self.service_detector.get_service_info(target, port)
                    return {
                        'port': port,
                        'status': 'open',
                        'scan_type': 'SYN',
                        **service_info
                    }
        except Exception as e:
            print(f"[SYN Scan] Error on port {port}: {e}")
        return None

    def udp_scan(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """UDP 스캔 (서비스 탐지는 제한적)"""
        try:
            packet = IP(dst=target) / UDP(dport=port)
            response = sr1(packet, timeout=self.timeout, verbose=0)
            if not response:
                print(f"[UDP Scan] Port {port} is open or filtered")
                return {
                    'port': port,
                    'status': 'open/filtered',
                    'scan_type': 'UDP',
                    'service': 'Unknown',
                    'banner': 'No banner (UDP)',
                    'protocol': 'UDP'
                }
        except Exception as e:
            print(f"[UDP Scan] Error on port {port}: {e}")
        return None

    def scan_ports(self, target: str, start_port: int, end_port: int, scan_type: str) -> List[Dict[str, Any]]:
        """스캔 메인 함수"""
        print(f"\n[*] Starting {scan_type} scan on {target} (Ports {start_port}-{end_port})")
        scan_results = []
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for port in range(start_port, end_port + 1):
                if scan_type == "TCP Connect":
                    future = executor.submit(self.tcp_connect_scan, target, port)
                elif scan_type == "SYN":
                    future = executor.submit(self.syn_scan, target, port)
                elif scan_type == "UDP":
                    future = executor.submit(self.udp_scan, target, port)
                futures.append(future)
            
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        scan_results.append(result)
                except Exception as e:
                    print(f"[-] Error in scan: {e}")
        
        return scan_results

def main():
    print("Advanced Port Scanner with Service Detection")
    target_ip = input("Enter target IP: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    print("\nChoose scan type:")
    print("1. TCP Connect (with service detection)")
    print("2. SYN Scan (with service detection)")
    print("3. UDP Scan (limited service detection)")
    scan_choice = input("Enter your choice (1-3): ")

    scanner = AdvancedPortScanner()
    scan_type = {
        "1": "TCP Connect",
        "2": "SYN",
        "3": "UDP"
    }.get(scan_choice)

    if not scan_type:
        print("Invalid choice. Exiting.")
        return

    results = scanner.scan_ports(target_ip, start_port, end_port, scan_type)
    
    # 결과 출력
    print("\n=== Scan Results ===")
    if results:
        for result in results:
            print(f"\n[+] Port {result['port']} ({result['scan_type']})")
            print(f"    Status: {result['status']}")
            print(f"    Service: {result['service']}")
            if result.get('banner') and result['banner'] != 'No banner':
                print(f"    Banner: {result['banner'][:100]}...")
    else:
        print("\n[-] No open ports found.")

if __name__ == "__main__":
    main() 
