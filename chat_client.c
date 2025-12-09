/**
 * Project: Clean-Chat Sentinel (Phase 2)
 * File: chat_client.c
 * Description: OpenSSL을 적용한 보안 채팅 클라이언트
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
#define NAME_SIZE 20

void *send_msg(void *arg);
void *recv_msg(void *arg);
void error_handling(char *msg);

char name[NAME_SIZE] = "[DEFAULT]";
char msg[BUF_SIZE];

int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in serv_addr;
    pthread_t snd_thread, rcv_thread;
    void *thread_return;

    // OpenSSL 구조체
    SSL_CTX *ctx;
    SSL *ssl;

    if (argc != 4) {
        printf("Usage : %s <IP> <port> <name>\n", argv[0]);
        exit(1);
    }

    sprintf(name, "[%s]", argv[3]);

    // 1. OpenSSL 초기화
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());

    if (!ctx) error_handling("SSL_CTX_new() failed");

    sock = socket(PF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
        error_handling("connect() error");

    // 2. SSL 객체 생성 및 핸드쉐이크
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) == -1) {
        printf("SSL Handshake failed!\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    printf(">> Connected to Secure Clean-Chat Server!\n");

    // SSL 객체를 스레드에 전달
    pthread_create(&snd_thread, NULL, send_msg, (void*)ssl);
    pthread_create(&rcv_thread, NULL, recv_msg, (void*)ssl);

    pthread_join(snd_thread, &thread_return);
    pthread_join(rcv_thread, &thread_return);

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return 0;
}

void *send_msg(void *arg)
{
    SSL *ssl = (SSL*)arg; // int sock 대신 SSL*을 받음
    char name_msg[NAME_SIZE + BUF_SIZE];
    
    while (1)
    {
        fgets(msg, BUF_SIZE, stdin);
        
        if (!strcmp(msg, "q\n") || !strcmp(msg, "Q\n"))
        {
            // 종료 로직은 메인 등에서 처리하도록 단순화 (여기선 생략)
            exit(0);
        }

        sprintf(name_msg, "%s %s", name, msg);
        // write() -> SSL_write()
        SSL_write(ssl, name_msg, strlen(name_msg));

        // UI Clean up
        printf("\033[1A\033[2K"); 
        fflush(stdout);
    }
    return NULL;
}

void *recv_msg(void *arg)
{
    SSL *ssl = (SSL*)arg;
    char name_msg[NAME_SIZE + BUF_SIZE];
    int str_len;
    
    while (1)
    {
        // read() -> SSL_read()
        str_len = SSL_read(ssl, name_msg, BUF_SIZE - 1);
        if (str_len <= 0) // 연결 끊김 or 에러
            return (void*)-1;
            
        name_msg[str_len] = 0;
        fputs(name_msg, stdout);
    }
    return NULL;
}

void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}