#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <json-c/json.h>

void scan_port(const char *ip, int port, json_object *json_results) {
    int sock;
    struct sockaddr_in server;

    // 소켓 생성
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        return;
    }

    // 서버 주소 설정
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server.sin_addr);

    // TCP Connect 시도
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == 0) {
        printf("Port %d is open\n", port);

        // JSON에 포트 상태 추가
        json_object *json_port = json_object_new_object();
        json_object_object_add(json_port, "host", json_object_new_string(ip));
        json_object_object_add(json_port, "port", json_object_new_int(port));
        json_object_object_add(json_port, "status", json_object_new_string("open"));
        json_object_array_add(json_results, json_port);
    }

    close(sock);
}

void save_nuclei_input(const char *filename, json_object *json_results) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Failed to create Nuclei input file");
        return;
    }

    for (int i = 0; i < json_object_array_length(json_results); i++) {
        json_object *entry = json_object_array_get_idx(json_results, i);
        const char *host = json_object_get_string(json_object_object_get(entry, "host"));
        int port = json_object_get_int(json_object_object_get(entry, "port"));

        // URL 형식으로 저장
        if (port == 443) {
            fprintf(file, "https://%s:%d\n", host, port);
        } else {
            fprintf(file, "http://%s:%d\n", host, port);
        }
    }

    fclose(file);
    printf("Nuclei input saved to %s\n", filename);
}

int main() {
    char ip[100];
    int start_port, end_port;

    printf("Enter IP address: ");
    scanf("%s", ip);

    printf("Enter start port: ");
    scanf("%d", &start_port);

    printf("Enter end port: ");
    scanf("%d", &end_port);

    // JSON 객체 생성
    json_object *json_results = json_object_new_array();

    printf("Scanning ports...\n");

    for (int port = start_port; port <= end_port; port++) {
        scan_port(ip, port, json_results);
    }

    // JSON 파일로 저장
    const char *json_filename = "scan_results.json";
    FILE *file = fopen(json_filename, "w");
    if (file) {
        fprintf(file, "%s\n", json_object_to_json_string_ext(json_results, JSON_C_TO_STRING_PRETTY));
        fclose(file);
        printf("Scan results saved to %s\n", json_filename);
    } else {
        perror("Failed to save results");
    }

    // Nuclei 입력 파일 생성
    const char *nuclei_filename = "nuclei_input.txt";
    save_nuclei_input(nuclei_filename, json_results);

    // JSON 객체 메모리 해제
    json_object_put(json_results);

    return 0;
}