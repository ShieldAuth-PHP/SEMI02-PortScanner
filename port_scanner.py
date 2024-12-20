import json
import os
import socket
from datetime import datetime

import boto3
import requests

# Shodan API 키
SHODAN_API_KEY = "Shodan API Key"

def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            return result == 0
    except Exception:
        return False

shodan_cache = {}

def get_shodan_info(ip, port):
    clean_ip = ip.replace("http://", "").replace("/", "")
    if clean_ip in shodan_cache:
        return shodan_cache[clean_ip]

    url = f"https://api.shodan.io/shodan/host/{clean_ip}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            shodan_cache[clean_ip] = data
            for item in data.get("data", []):
                if item.get("port") == port:
                    return {
                        "service": item.get("product", "Unknown"),
                        "version": item.get("version", "Unknown"),
                        "cve": item.get("vulns", [])
                    }
    except requests.RequestException as e:
        print(f"Error fetching Shodan info: {e}")
    return {"service": "Unknown", "version": "Unknown", "cve": ["No CVE available"]}

def save_results_to_file(results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_results_{timestamp}.json"
    try:
        with open(filename, "w") as f:
            json.dump(results, f, indent=4, separators=(",", ": "), ensure_ascii=False)
        print(f"Results successfully saved to {filename}")
    except Exception as e:
        print(f"Error saving results to file: {e}")

# AWS Lambda 클라이언트 생성
lambda_client = boto3.client("lambda", region_name="us-east-1")  # 적절한 리전으로 변경

def invoke_lambda(results):
    lambda_function_name = "your_lambda_function_name"  # 생성한 Lambda 함수 이름
    try:
        response = lambda_client.invoke(
            FunctionName=lambda_function_name,
            InvocationType="RequestResponse",  # 동기 실행
            Payload=json.dumps({"data": results}),
        )
        response_payload = json.loads(response["Payload"].read())
        print(f"Lambda response: {response_payload}")
    except Exception as e:
        print(f"Error invoking Lambda: {e}")

def main():
    host = input("Enter IP address to scan: ").strip()
    if not validate_ip(host):
        return
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))

    results = []
    for port in range(start_port, end_port + 1):
        print(f"Scanning port {port}...")
        if scan_port(host, port):
            print(f"Port {port} is open")
            shodan_info = get_shodan_info(host, port)
            results.append({
                "host": host,
                "port": port,
                "status": "open",
                "service": shodan_info.get("service"),
                "version": shodan_info.get("version"),
                "cve": shodan_info.get("cve"),
            })

    save_results_to_file(results)
    invoke_lambda(results)  # Lambda 호출


if __name__ == "__main__":
    main()
