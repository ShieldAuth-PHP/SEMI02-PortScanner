import socket
import logging
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional
import json
import argparse
from dataclasses import dataclass, asdict
from enum import Enum, auto

class LogLevel(Enum):
    DEBUG = auto()
    INFO = auto()
    WARNING = auto()
    ERROR = auto()
    CRITICAL = auto()

class NetworkScannerConfig:
    """
    네트워크 스캐닝을 위한 고급 구성 관리
    
    주요 기능:
    - 세부 타임아웃 설정
    - 병렬 처리 스레드 수 조정
    - 로깅 수준 및 로그 파일 구성
    """
    def __init__(
        self, 
        timeout: int = 2, 
        max_workers: int = 50, 
        log_level: LogLevel = LogLevel.INFO,
        log_file: Optional[str] = None,
        retry_count: int = 1,
        ports: Optional[List[int]] = None
    ):
        self.timeout = timeout
        self.max_workers = max_workers
        self.log_level = log_level
        self.log_file = log_file
        self.retry_count = retry_count
        self.ports = ports or [21, 22, 23, 80, 443]

    def configure_logging(self) -> logging.Logger:
        """
        로깅 시스템 고급 구성
        
        Returns:
            logging.Logger: 구성된 로거 객체
        """
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        log_level_map = {
            LogLevel.DEBUG: logging.DEBUG,
            LogLevel.INFO: logging.INFO,
            LogLevel.WARNING: logging.WARNING,
            LogLevel.ERROR: logging.ERROR,
            LogLevel.CRITICAL: logging.CRITICAL
        }

        # 로거 생성
        logger = logging.getLogger('NetworkScanner')
        logger.setLevel(log_level_map[self.log_level])

        # 포맷터 설정
        formatter = logging.Formatter(log_format)

        # 콘솔 핸들러 추가
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # 파일 로깅 옵션 (선택적)
        if self.log_file:
            file_handler = logging.FileHandler(self.log_file, mode='a')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        return logger

@dataclass
class PortInfo:
    """포트 정보를 위한 데이터 클래스"""
    ip: str
    port: int
    status: str
    service: str
    banner: Optional[str] = None
    timestamp: Optional[str] = None

    def __post_init__(self):
        """객체 생성 후 추가 초기화"""
        self.timestamp = datetime.now().isoformat()

class SecureServiceDetector:
    """고급 서비스 및 배너 탐지 클래스"""
    def __init__(self, config: NetworkScannerConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger

    def validate_ip(self, ip: str) -> bool:
        """IP 주소 유효성 검사"""
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            self.logger.error(f"잘못된 IP 주소 형식: {ip}")
            return False

    def get_banner(self, ip: str, port: int) -> Optional[PortInfo]:
        """
        포트 배너 정보 수집 및 서비스 탐지
        보안을 고려한 배너 수집 메서드
        """
        if not self.validate_ip(ip):
            return None

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.config.timeout)
                
                # 연결 시도
                result = sock.connect_ex((ip, port))
                if result != 0:
                    return PortInfo(
                        ip=ip, 
                        port=port, 
                        status='Closed', 
                        service='Unknown',
                        banner=None
                    )

                # 프로토콜별 특화된 배너 수집
                banner = self._collect_protocol_specific_banner(sock, ip, port)
                service = self._detect_service(banner)

                return PortInfo(
                    ip=ip, 
                    port=port, 
                    status='Open', 
                    service=service,
                    banner=banner
                )

        except Exception as e:
            self.logger.error(f"포트 {port} 스캔 중 오류: {e}")
            return None

    def _collect_protocol_specific_banner(
        self, 
        sock: socket.socket, 
        ip: str, 
        port: int
    ) -> Optional[str]:
        """프로토콜별 특화된 배너 수집"""
        try:
            if port in [80, 443]:
                if port == 443:
                    sock = ssl.wrap_socket(sock)
                
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            elif port == 22:  # SSH
                sock.send(b"SSH-2.0-OpenSSH_8.1\r\n")
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            elif port == 25:  # SMTP
                sock.send(b"HELO test\r\n")
                return sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            return None
        except Exception as e:
            self.logger.warning(f"배너 수집 중 오류 (포트 {port}): {e}")
            return None

    def _detect_service(self, banner: Optional[str]) -> str:
        """
        배너 기반 서비스 탐지
        기계 학습 기반 서비스 탐지를 위한 확장 가능 구조
        """
        if not banner:
            return "Unknown"

        banner = banner.lower()
        service_map = {
            'http/': 'HTTP Server',
            'ssh-': 'SSH Server',
            'smtp': 'SMTP Server',
            'ftp': 'FTP Server'
        }

        for key, service in service_map.items():
            if key in banner:
                return service

        return "Unknown Service"

class AdvancedPortScanner:
    """
    다중 프로토콜, 포트 스캐닝 클래스
    """
    def __init__(self, config: NetworkScannerConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.service_detector = SecureServiceDetector(config, logger)
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            27017: "MongoDB"
        }

    def scan_ports(self, ip: str, ports: List[int]) -> List[PortInfo]:
        """포트 스캐닝 메서드"""
        results: List[PortInfo] = []

        try:
            with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
                futures = {
                    executor.submit(
                        self.service_detector.get_banner, 
                        ip, 
                        port
                    ): port for port in ports
                }

                for future in as_completed(futures):
                    port_info = future.result()
                    if port_info and port_info.status == 'Open':
                        results.append(port_info)
                        self.logger.info(f"포트 {port_info.port} 열림: {port_info.service}")

        except Exception as e:
            self.logger.error(f"포트 스캐닝 중 심각한 오류 발생: {e}")

        return results

    def export_results(self, results: List[PortInfo], format: str = 'json', output_file: Optional[str] = None) -> None:
        """스캔 결과 내보내기"""
        formatted_results = [asdict(result) for result in results]

        if format == 'json':
            output = json.dumps(formatted_results, indent=2, ensure_ascii=False)
        elif format == 'table':  # 새로운 테이블 형식 추가
            headers = ["IP", "Port", "Status", "Service", "Banner"]
            rows = [[
                r['ip'],
                r['port'],
                r['status'],
                r['service'],
                (r['banner'][:50] + '...') if r['banner'] else 'N/A'
            ] for r in formatted_results]
            
            # 테이블 형식으로 출력
            output = self._format_table(headers, rows)
        else:
            raise ValueError("지원되지 않는 형식입니다.")

        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
        else:
            print(output)

    def _format_table(self, headers: List[str], rows: List[List[str]]) -> str:
        """테이블 형식으로 데이터 포맷팅"""
        # 컬럼 너비 조정
        col_widths = {
            "IP": 15,
            "Port": 6,
            "Status": 8,
            "Service": 15,
            "Banner": 50
        }
        
        # 헤더 스타일
        separator = "+" + "+".join("-" * (col_widths[h] + 2) for h in headers) + "+"
        
        result = [separator]
        header = "| " + " | ".join(f"{h:<{col_widths[h]}}" for h in headers) + " |"
        result.append(header)
        result.append(separator)
        
        # 데이터 행 포맷팅
        for row in rows:
            formatted_row = []
            for i, cell in enumerate(row):
                width = col_widths[headers[i]]
                if headers[i] == "Banner" and cell != "N/A":
                    # 배너 텍스트 정리
                    cell = cell.split('\r\n')[0][:width]  # 첫 줄만 표시
                formatted_row.append(f"{str(cell):<{width}}")
            
            result.append("| " + " | ".join(formatted_row) + " |")
        
        result.append(separator)
        return "\n".join(result)

    def scan_range(self, start_ip: str, end_ip: str) -> Dict[str, List[PortInfo]]:
        """IP 범위 스캔"""
        results = {}
        start = list(map(int, start_ip.split('.')))
        end = list(map(int, end_ip.split('.')))
        
        temp = start[:]
        while temp <= end:
            current_ip = '.'.join(map(str, temp))
            results[current_ip] = self.scan_ports(current_ip, self.config.ports)
            
            # 다음 IP 주소로
            temp[3] += 1
            for i in (3, 2, 1):
                if temp[i] == 256:
                    temp[i] = 0
                    temp[i-1] += 1

        return results

    def scan_common_ports(self, ip: str) -> List[PortInfo]:
        """일반적인 서비스 포트만 스캔"""
        return self.scan_ports(ip, list(self.common_ports.keys()))

    def get_service_info(self, port: int) -> str:
        """포트 번호에 해당하는 일반적인 서비스 정보 반환"""
        return self.common_ports.get(port, "Unknown")

def main():
    """포트 스캐너 메인 함수"""
    parser = argparse.ArgumentParser(description="고급 포트 스캐닝 도구")
    parser.add_argument("ip", help="스캔할 대상 IP 주소")
    parser.add_argument("-p", "--ports", nargs="+", type=int, help="스캔할 포트 목록 (기본값: 일반 서비스 포트)")
    parser.add_argument("--timeout", type=int, default=2, help="연결 타임아웃 (초)")
    parser.add_argument("--max-workers", type=int, default=50, help="최대 병렬 처리 스레드 수")
    parser.add_argument("--log-level", choices=[l.name for l in LogLevel], default=LogLevel.INFO.name, help="로깅 레벨")
    parser.add_argument("--log-file", help="로그 파일 경로")
    parser.add_argument("--output", help="결과 출력 파일")
    parser.add_argument("--retry", type=int, default=1, help="연결 재시도 횟수")
    parser.add_argument("--format", choices=['json', 'table'], default='table', help="출력 형식")
    parser.add_argument("--range", help="IP 범위 스캔 (예: 192.168.1.1-192.168.1.254)")
    parser.add_argument("--common", action="store_true", help="일반적인 서비스 포트만 스캔")

    args = parser.parse_args()

    config = NetworkScannerConfig(
        timeout=args.timeout,
        max_workers=args.max_workers,
        log_level=LogLevel[args.log_level],
        log_file=args.log_file,
        retry_count=args.retry,
        ports=args.ports
    )
    
    # 로깅 시스템 초기화
    logger = config.configure_logging()

    scanner = AdvancedPortScanner(config, logger)
    # IP 범위 처리
    if args.range:
        start_ip, end_ip = args.range.split('-')
        results = scanner.scan_range(start_ip.strip(), end_ip.strip())
    # 일반 포트 스캔
    elif args.common:
        results = scanner.scan_common_ports(args.ip)
    # 기본 스캔
    else:
        results = scanner.scan_ports(args.ip, config.ports)
    
    scanner.export_results(results, format=args.format, output_file=args.output)

if __name__ == "__main__":
    main()
