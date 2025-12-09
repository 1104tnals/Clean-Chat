/**
 * Project: Clean-Chat Sentinel (Final Integration)
 * File: chat_server.c
 * Description: OpenSSL 보안 + 대량 욕설 필터링 + 3진 아웃 차단 채팅 서버
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE 100
#define MAX_CLNT 256

// ANSI 색상 코드 (UI)
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_GREEN   "\033[32m"

// 욕설 데이터 구조체
typedef struct {
    char *pattern;      // 감지할 단어 (파일에서 읽음)
    char *replacement;  // 바뀔 단어 (무조건 "**")
} BadWordMsg;

// 클라이언트 정보 구조체
typedef struct {
    int socket;
    SSL *ssl;
    struct sockaddr_in address;
    int warning_count;  // 경고 누적 횟수
} ClientInfo;

// 전역 변수
BadWordMsg *bad_words_list = NULL; // 동적 욕설 리스트
int bad_word_count = 0;

ClientInfo *clnt_infos[MAX_CLNT];
int clnt_cnt = 0;

pthread_mutex_t mutx;
SSL_CTX *ctx;

// 함수 선언
void load_bad_words(const char *filename);
int filter_logic(char *msg);
void *handle_clnt(void *arg);
void send_msg(char *msg, int len);
void error_handling(char *msg);

int main(int argc, char *argv[])
{
    int serv_sock, clnt_sock;
    struct sockaddr_in serv_adr, clnt_adr;
    socklen_t clnt_adr_sz;
    pthread_t t_id;

    if (argc != 2) {
        printf("Usage : %s <port>\n", argv[0]);
        exit(1);
    }

    // 1. 욕설 데이터셋 로딩 (대량 데이터 지원)
    load_bad_words("badwords.txt");

    // 2. OpenSSL 초기화
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_server_method());

    if (!ctx) error_handling("SSL_CTX_new() failed");

    // 인증서 로드 (server.crt, server.key 필수)
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
        error_handling("Failed to load certificate");
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
        error_handling("Failed to load private key");

    pthread_mutex_init(&mutx, NULL);
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);

    // [Bind Error 방지] 포트 재사용 옵션 설정
    int option = 1;
    setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(atoi(argv[1]));

    if (bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
        error_handling("bind() error");
    if (listen(serv_sock, 5) == -1)
        error_handling("listen() error");
    
    printf("\n============ Clean-Chat Started <Port: %s> ============\n\n", argv[1]);

    while (1)
    {
        clnt_adr_sz = sizeof(clnt_adr);
        clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);
        
        // SSL 객체 생성 및 연결
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clnt_sock);

        if (SSL_accept(ssl) == -1) {
            printf("[-] SSL Handshake failed!\n");
            close(clnt_sock);
            SSL_free(ssl);
            continue;
        }

        // 클라이언트 정보 등록
        pthread_mutex_lock(&mutx);
        ClientInfo *new_clnt = (ClientInfo*)malloc(sizeof(ClientInfo));
        new_clnt->socket = clnt_sock;
        new_clnt->ssl = ssl;
        new_clnt->address = clnt_adr;
        new_clnt->warning_count = 0; // 초기화
        clnt_infos[clnt_cnt++] = new_clnt;
        pthread_mutex_unlock(&mutx);

        // 스레드 생성
        pthread_create(&t_id, NULL, handle_clnt, (void*)new_clnt);
        pthread_detach(t_id);
        
        printf("[+] Connected Client: %s \n", inet_ntoa(clnt_adr.sin_addr));
    }

    // 서버 종료 시 자원 해제 (Unreachable in this loop)
    SSL_CTX_free(ctx);
    close(serv_sock);
    return 0;
}

// -----------------------------------------------------------
// [핵심 기능 1] 대량 데이터셋 로딩 (무조건 **로 치환)
// -----------------------------------------------------------
void load_bad_words(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("[-] Failed to open badwords.txt");
        printf("[-] Warning: Running without filter!\n");
        return;
    }

    char line[256];
    int capacity = 100;
    
    if (bad_words_list != NULL) free(bad_words_list);
    bad_words_list = (BadWordMsg*)malloc(sizeof(BadWordMsg) * capacity);
    bad_word_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        // 줄바꿈 제거 (윈도우/리눅스 호환)
        line[strcspn(line, "\r\n")] = 0;
        
        if (strlen(line) == 0) continue;

        // 배열 공간 부족 시 2배 확장
        if (bad_word_count >= capacity) {
            capacity *= 2;
            BadWordMsg *temp = (BadWordMsg*)realloc(bad_words_list, sizeof(BadWordMsg) * capacity);
            if (!temp) {
                printf("[-] Memory allocation failed!\n");
                break;
            }
            bad_words_list = temp;
        }

        // 패턴은 파일 내용 그대로, 치환은 무조건 "**"
        bad_words_list[bad_word_count].pattern = strdup(line);
        bad_words_list[bad_word_count].replacement = strdup("**"); 
        bad_word_count++;
    }

    fclose(fp);
}

// -----------------------------------------------------------
// [핵심 기능 2] 필터링 엔진 (메모리 당기기 적용)
// -----------------------------------------------------------
int filter_logic(char *msg)
{
    int detected = 0;
    char *ptr = NULL;
    
    for (int i = 0; i < bad_word_count; i++) {
        // 해당 욕설이 문자열에 있는지 계속 검색
        while ((ptr = strstr(msg, bad_words_list[i].pattern)) != NULL) {
            detected = 1;
            
            int pattern_len = strlen(bad_words_list[i].pattern);     // 예: "씨발" (6바이트)
            int replace_len = strlen(bad_words_list[i].replacement); // 예: "**" (2바이트)
            
            // 1. 치환할 문자로 덮어씀
            memcpy(ptr, bad_words_list[i].replacement, replace_len);
            
            // 2. 길이 차이만큼 뒤에 있는 문자열을 앞으로 당겨옴 (빈 공간 삭제)
            int diff = pattern_len - replace_len;
            if (diff > 0) {
                memmove(ptr + replace_len, ptr + pattern_len, strlen(ptr + pattern_len) + 1);
            }
        }
    }
    return detected;
}

// -----------------------------------------------------------
// [핵심 기능 3] 클라이언트 핸들러 & 3진 아웃 로직
// -----------------------------------------------------------
// [수정됨] 순서 변경: 메시지 전송 -> 시스템 경고
void *handle_clnt(void *arg)
{
    ClientInfo *clnt = (ClientInfo*)arg;
    int str_len = 0;
    char msg[BUF_SIZE];
    char sys_msg[BUF_SIZE];

    while ((str_len = SSL_read(clnt->ssl, msg, sizeof(msg))) > 0)
    {
        msg[str_len] = 0;

        // 1. 필터링 수행 (결과를 변수에 저장)
        int is_abusive = filter_logic(msg);

        // 2. [순서 변경] 채팅방에 메시지 먼저 전송 (필터링된 내용)
        // 이렇게 해야 사용자 화면에 [**]가 먼저 뜨고, 그 아래에 경고문이 뜹니다.
        send_msg(msg, strlen(msg));

        // 3. 욕설이 감지된 경우 후속 처리 (경고 및 차단)
        if (is_abusive) 
        {
            clnt->warning_count++;
            
            if (clnt->warning_count >= 3) 
            {
                // [3진 아웃] 차단 메시지 전송
                sprintf(sys_msg, "%s[SYSTEM] WARNING(3/3): 욕설이 3회 이상 감지되어 차단됩니다.%s\n", COLOR_RED, COLOR_RESET);
                SSL_write(clnt->ssl, sys_msg, strlen(sys_msg));
                
                printf("%s[!] Banned User: %s%s\n", COLOR_RED, inet_ntoa(clnt->address.sin_addr), COLOR_RESET);
                break; // 루프 탈출 -> 연결 종료
            }
            else 
            {
                // [경고] 경고 메시지 전송
                sprintf(sys_msg, "%s[SYSTEM] WARNING(%d/3): 비속어가 감지되었습니다.%s\n", 
                        COLOR_YELLOW, clnt->warning_count, COLOR_RESET);
                SSL_write(clnt->ssl, sys_msg, strlen(sys_msg));
            }
        }
    }

    // --- 연결 종료 및 자원 정리 ---
    pthread_mutex_lock(&mutx);
    for (int i = 0; i < clnt_cnt; i++) {
        if (clnt->socket == clnt_infos[i]->socket) {
            while (i++ < clnt_cnt - 1)
                clnt_infos[i] = clnt_infos[i + 1];
            break;
        }
    }
    clnt_cnt--;
    pthread_mutex_unlock(&mutx);

    printf("%s[-] User Disconnected: %s%s\n", COLOR_YELLOW, inet_ntoa(clnt->address.sin_addr), COLOR_RESET);

    SSL_shutdown(clnt->ssl);
    SSL_free(clnt->ssl);
    close(clnt->socket);
    free(clnt);
    
    return NULL;
}
void send_msg(char *msg, int len)
{
    pthread_mutex_lock(&mutx);
    for (int i = 0; i < clnt_cnt; i++)
        SSL_write(clnt_infos[i]->ssl, msg, len);
    pthread_mutex_unlock(&mutx);
}

void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    ERR_print_errors_fp(stderr); // OpenSSL 에러 상세 출력
    exit(1);
}