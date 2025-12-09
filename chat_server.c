/**
 * Project: Clean-Chat Sentinel (Phase 3)
 * File: chat_server.c
 * Description: OpenSSL + 욕설 필터링 + 3진 아웃 차단 시스템
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
#define MAX_BAD_WORDS 10

// 색상 코드 (ANSI Escape Codes)
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_GREEN   "\033[32m"

// 금지어 목록
const char *BAD_WORDS[MAX_BAD_WORDS] = {
    "바보", "멍청이", "씨발", "개새끼", "병신", 
    "지랄", "닥쳐", "꺼져", "미친", "죽어"
};

// 클라이언트 정보 구조체 (경고 횟수 추가)
typedef struct {
    int socket;
    SSL *ssl;
    struct sockaddr_in address;
    int warning_count; // 3진 아웃 카운터
} ClientInfo;

void *handle_clnt(void *arg);
void send_msg(char *msg, int len);
void error_handling(char *msg);
int filter_logic(char *msg); // 필터링 함수

ClientInfo *clnt_infos[MAX_CLNT]; 
int clnt_cnt = 0;

pthread_mutex_t mutx;
SSL_CTX *ctx;

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

    // OpenSSL 초기화
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_server_method());

    if (!ctx) error_handling("SSL_CTX_new() failed");

    // 인증서 로드 (Phase 2와 동일)
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
        error_handling("Failed to load certificate");
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
        error_handling("Failed to load private key");

    pthread_mutex_init(&mutx, NULL);

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);

    // [Bind Error 방지] 포트 재사용 옵션
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
    
    printf(">> Clean-Chat Sentinel (Phase 3: Filtering Active) Started...\n");

    while (1)
    {
        clnt_adr_sz = sizeof(clnt_adr);
        clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);
        
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clnt_sock);

        if (SSL_accept(ssl) == -1) {
            printf("SSL Handshake failed!\n");
            close(clnt_sock);
            SSL_free(ssl);
            continue;
        }

        pthread_mutex_lock(&mutx);
        ClientInfo *new_clnt = (ClientInfo*)malloc(sizeof(ClientInfo));
        new_clnt->socket = clnt_sock;
        new_clnt->ssl = ssl;
        new_clnt->address = clnt_adr;
        new_clnt->warning_count = 0; // 경고 횟수 초기화
        clnt_infos[clnt_cnt++] = new_clnt;
        pthread_mutex_unlock(&mutx);

        pthread_create(&t_id, NULL, handle_clnt, (void*)new_clnt);
        pthread_detach(t_id);
        
        printf("Client Connected: %s \n", inet_ntoa(clnt_adr.sin_addr));
    }

    SSL_CTX_free(ctx);
    close(serv_sock);
    return 0;
}

// [업그레이드] 욕설 길이만큼 *로 마스킹하는 안전한 로직
int filter_logic(char *msg)
{
    int detected = 0;
    int word_len;
    
    for (int i = 0; i < MAX_BAD_WORDS; i++) {
        char *ptr = strstr(msg, BAD_WORDS[i]); // 욕설 검색
        
        while (ptr != NULL) {
            detected = 1;
            word_len = strlen(BAD_WORDS[i]); // 욕설의 바이트 길이 계산
            
            // 발견된 욕설의 길이만큼 '*'로 덮어쓰기 (메모리 오염 방지)
            memset(ptr, '*', word_len); 
            
            // 다음 욕설 검색
            ptr = strstr(ptr + word_len, BAD_WORDS[i]); 
        }
    }
    return detected;
}

void *handle_clnt(void *arg)
{
    ClientInfo *clnt = (ClientInfo*)arg;
    int str_len = 0;
    char msg[BUF_SIZE];
    char sys_msg[BUF_SIZE]; // 시스템 알림용 버퍼

    while ((str_len = SSL_read(clnt->ssl, msg, sizeof(msg))) > 0)
    {
        msg[str_len] = 0; // 문자열 끝 처리

        // [핵심 로직] 필터링 수행
        if (filter_logic(msg)) 
        {
            // 욕설이 감지된 경우
            clnt->warning_count++;
            
            if (clnt->warning_count >= 3) 
            {
                // [3진 아웃] 차단 처리
                sprintf(sys_msg, "%s[SYSTEM] 경고(3/3): 욕설 사용 누적으로 차단됩니다. Bye!%s\n", COLOR_RED, COLOR_RESET);
                SSL_write(clnt->ssl, sys_msg, strlen(sys_msg));
                printf("!!! Banned Client: %s (Strikes: 3)\n", inet_ntoa(clnt->address.sin_addr));
                break; // while 루프 탈출 -> 연결 종료
            }
            else 
            {
                // [경고] 경고 메시지 전송
                sprintf(sys_msg, "%s[SYSTEM] 경고(%d/3): 비속어가 감지되었습니다. 바른말을 써주세요.%s\n", 
                        COLOR_YELLOW, clnt->warning_count, COLOR_RESET);
                SSL_write(clnt->ssl, sys_msg, strlen(sys_msg));
            }
        }

        // (마스킹된) 메시지를 채팅방 전체에 전송
        send_msg(msg, strlen(msg));
    }

    // 연결 종료 처리
    pthread_mutex_lock(&mutx);
    for (int i = 0; i < clnt_cnt; i++)
    {
        if (clnt->socket == clnt_infos[i]->socket)
        {
            while (i++ < clnt_cnt - 1)
                clnt_infos[i] = clnt_infos[i + 1];
            break;
        }
    }
    clnt_cnt--;
    pthread_mutex_unlock(&mutx);

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
    ERR_print_errors_fp(stderr);
    exit(1);
}