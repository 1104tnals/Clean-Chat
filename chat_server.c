/**
 * Project: Clean-Chat Sentinel (Phase 2)
 * File: chat_server.c
 * Description: OpenSSL을 적용한 보안 채팅 서버
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

// 클라이언트 정보를 담는 구조체 (Socket + SSL)
typedef struct {
    int socket;
    SSL *ssl;
    struct sockaddr_in address;
} ClientInfo;

void *handle_clnt(void *arg);
void send_msg(char *msg, int len);
void error_handling(char *msg);

// 공유 자원: 클라이언트 객체 배열
ClientInfo *clnt_infos[MAX_CLNT]; 
int clnt_cnt = 0;

pthread_mutex_t mutx;
SSL_CTX *ctx; // SSL 컨텍스트 (공장 같은 역할)

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

    // 1. OpenSSL 초기화 및 컨텍스트 생성
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_server_method();
    ctx = SSL_CTX_new(method);

    if (!ctx) error_handling("SSL_CTX_new() failed");

    // 2. 인증서와 키 로드
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
        error_handling("Failed to load certificate");
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
        error_handling("Failed to load private key");

    pthread_mutex_init(&mutx, NULL);

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(atoi(argv[1]));

    if (bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
        error_handling("bind() error");
    if (listen(serv_sock, 5) == -1)
        error_handling("listen() error");
    
    printf(">> Clean-Chat Sentinel (Secure Server) Started...\n");

    while (1)
    {
        clnt_adr_sz = sizeof(clnt_adr);
        clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);
        
        // 3. SSL 객체 생성 및 연결
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clnt_sock);

        // SSL Handshake (보안 협상)
        if (SSL_accept(ssl) == -1) {
            printf("SSL Handshake failed!\n");
            ERR_print_errors_fp(stderr);
            close(clnt_sock);
            SSL_free(ssl);
            continue;
        }

        // 클라이언트 정보 구조체 생성 및 등록
        pthread_mutex_lock(&mutx);
        ClientInfo *new_clnt = (ClientInfo*)malloc(sizeof(ClientInfo));
        new_clnt->socket = clnt_sock;
        new_clnt->ssl = ssl;
        new_clnt->address = clnt_adr;
        clnt_infos[clnt_cnt++] = new_clnt;
        pthread_mutex_unlock(&mutx);

        pthread_create(&t_id, NULL, handle_clnt, (void*)new_clnt);
        pthread_detach(t_id);
        
        printf("Connected Secure client IP: %s \n", inet_ntoa(clnt_adr.sin_addr));
    }

    // 종료 처리 (실제로는 unreachable code)
    SSL_CTX_free(ctx);
    close(serv_sock);
    return 0;
}

void *handle_clnt(void *arg)
{
    ClientInfo *clnt = (ClientInfo*)arg;
    int str_len = 0;
    char msg[BUF_SIZE];

    // read() 대신 SSL_read() 사용
    while ((str_len = SSL_read(clnt->ssl, msg, sizeof(msg))) > 0)
        send_msg(msg, str_len);

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

    // 자원 해제
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
        // write() 대신 SSL_write() 사용
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