import os
import socket
import json
import requests
from datetime import datetime
from dotenv import load_dotenv
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# .env 파일에서 환경 변수 로드
load_dotenv()

# API URL 설정
SHODAN_API_URL = "https://internetdb.shodan.io/"
GEOPING_API_URL = "https://geonet.shodan.io/api/geoping/"
DEFAULT_PORTS = [80, 443, 22, 21, 25, 3389, 8080, 53]

def get_shodan_data(ip: str) -> dict:
    """Shodan 데이터를 가져옵니다."""
    try:
        response = requests.get(f"{SHODAN_API_URL}{ip}")
        return response.json() if response.status_code == 200 else {"error": response.text}
    except Exception as e:
        return {"error": str(e)}

def get_geoping_data(ip: str) -> list:
    """GeoPing 데이터를 가져옵니다."""
    try:
        response = requests.get(f"{GEOPING_API_URL}{ip}")
        return response.json() if response.status_code == 200 else [{"error": response.text}]
    except Exception as e:
        return [{"error": str(e)}]

def scan_port(ip: str, port: int) -> dict:
    """포트를 스캔하여 상태와 배너 정보를 반환합니다."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    banner = sock.recv(1024).decode().strip()
                except:
                    banner = "No Banner"
                return {"port": port, "status": "open", "banner": banner}
    except:
        pass
    return {"port": port, "status": "closed", "banner": ""}

def scan_ports(ip: str, ports: list) -> list:
    """멀티스레드를 사용해 포트를 스캔합니다."""
    with ThreadPoolExecutor(max_workers=10) as executor:
        return list(executor.map(lambda port: scan_port(ip, port), ports))

def analyze_geoping_data(geoping_data: list) -> dict:
    """GeoPing 데이터를 기반으로 서비스 상태를 평가합니다."""
    total_locations = len(geoping_data)
    unreachable = sum(1 for geo in geoping_data if not geo.get("is_alive"))
    return {
        "total_locations": total_locations,
        "unreachable": unreachable,
        "reachable": total_locations - unreachable,
        "issues": [
            f"{geo['from_loc']['city']}, {geo['from_loc']['country']}에서 서비스 비가용"
            for geo in geoping_data if not geo.get("is_alive")
        ],
    }

def analyze_ports(scan_results: list) -> dict:
    """포트 스캔 데이터를 분석합니다."""
    open_ports = [res['port'] for res in scan_results if res['status'] == "open"]
    high_risk_ports = [port for port in open_ports if port in [21, 23, 25, 3389]]
    return {
        "open_ports": open_ports,
        "high_risk_ports": high_risk_ports,
        "risk_level": "High" if high_risk_ports else "Low"
    }

def display_results(ip: str, shodan_data: dict, geoping_summary: dict, port_summary: dict):
    """결과를 CLI에 출력합니다."""
    def section_header(title: str):
        print(f"\n{'='*20} {title} {'='*20}\n")

    print("\n" + "=" * 60)
    print(f"          Comprehensive Analysis for {ip}")
    print("=" * 60)

    # Shodan 정보
    section_header("Shodan 정보")
    print(f"    호스트 이름: {', '.join(shodan_data.get('hostnames', [])) or 'N/A'}")
    print(f"    태그: {', '.join(shodan_data.get('tags', [])) or 'N/A'}")
    print(f"    감지된 포트: {', '.join(map(str, shodan_data.get('ports', []))) or 'N/A'}")
    print(f"    감지된 취약점: {', '.join(shodan_data.get('vulns', [])) or '없음'}")

    # GeoPing 요약
    section_header("GeoPing 요약")
    print(f"    테스트된 지역: {geoping_summary['total_locations']}")
    print(f"    연결 가능한 지역: {geoping_summary['reachable']}")
    print(f"    연결 불가능한 지역: {geoping_summary['unreachable']}")
    if geoping_summary["issues"]:
        print("    문제 지역:")
        for issue in geoping_summary["issues"]:
            print(f"        - {issue}")

    # 포트 스캔 요약
    section_header("포트 스캔 요약")
    print(f"    열린 포트: {', '.join(map(str, port_summary['open_ports'])) or 'N/A'}")
    print(f"    고위험 포트: {', '.join(map(str, port_summary['high_risk_ports'])) or '없음'}")
    print(f"    보안 수준: {port_summary['risk_level']}")

    print("\n" + "=" * 60)

def save_results(ip: str, shodan_data: dict, geoping_data: list, scan_results: list, insights: dict):
    """결과를 JSON 파일로 저장합니다."""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    results = {
        "ip": ip,
        "timestamp": timestamp,
        "shodan_data": shodan_data,
        "geoping_data": geoping_data,
        "scan_results": scan_results,
        "insights": insights
    }
    results_folder = Path("results")
    results_folder.mkdir(exist_ok=True)  # 폴더 생성
    output_file = results_folder / f"scan_results_{timestamp}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=4)
    return output_file

def main():
    target_ip = input("스캔할 대상 IP를 입력하세요: ").strip()
    if not target_ip:
        print("[!] 유효한 IP를 입력하세요.")
        return

    print("\n[+] 데이터 수집 중...")
    shodan_data = get_shodan_data(target_ip)
    geoping_data = get_geoping_data(target_ip)
    scan_results = scan_ports(target_ip, DEFAULT_PORTS)

    print("\n[+] 데이터 분석 중...")
    geoping_summary = analyze_geoping_data(geoping_data)
    port_summary = analyze_ports(scan_results)

    display_results(target_ip, shodan_data, geoping_summary, port_summary)

    insights = {
        "geo_summary": geoping_summary,
        "port_summary": port_summary
    }
    output_file = save_results(target_ip, shodan_data, geoping_data, scan_results, insights)
    print(f"\n[+] 결과가 {output_file} 파일에 저장되었습니다.")

if __name__ == "__main__":
    main()
