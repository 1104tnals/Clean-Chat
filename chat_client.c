/**
 * Project: Clean-Chat Sentinel (Client Final Release)
 * Description: OpenSSL 보안 적용 및 차단 시 즉시 종료되는 클라이언트
 * Step-by-Step Comments Added
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

// UI 색상 매크로
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"

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

    // OpenSSL 관련 구조체
    SSL_CTX *ctx;
    SSL *ssl;

    if (argc != 4) {
        printf("Usage : %s <IP> <port> <name>\n", argv[0]);
        exit(1);
    }

    sprintf(name, "[%s]", argv[3]);

    // 1. OpenSSL 초기화 및 컨텍스트(Context) 설정
    SSL_library_init();                 // 라이브러리 로드
    OpenSSL_add_all_algorithms();       // 암호화 알고리즘 로드
    SSL_load_error_strings();           // 에러 메시지 로드
    ctx = SSL_CTX_new(TLS_client_method()); // 클라이언트용 메서드 생성

    if (!ctx) error_handling("SSL_CTX_new() failed");

    // 2. 소켓 생성 및 서버 연결 (TCP Handshake)
    sock = socket(PF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
        error_handling("connect() error");

    // 3. SSL 객체 생성 및 보안 핸드쉐이크 (SSL Handshake)
    ssl = SSL_new(ctx);      // SSL 구조체 생성
    SSL_set_fd(ssl, sock);   // 소켓과 SSL 연결

    if (SSL_connect(ssl) == -1) { // 보안 터널 형성 시도
        printf("SSL Handshake failed!\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    printf("\n============ Connected to Clean-Chat Server! (Secure) ============\n\n");

    // 4. 송신/수신 스레드 분리 및 생성
    // send_msg: 키보드 입력 -> 암호화 -> 전송
    // recv_msg: 수신 -> 복호화 -> 화면 출력 (종료 감지 포함)
    pthread_create(&snd_thread, NULL, send_msg, (void*)ssl);
    pthread_create(&rcv_thread, NULL, recv_msg, (void*)ssl);

    pthread_join(snd_thread, &thread_return);
    pthread_join(rcv_thread, &thread_return);

    // 5. 자원 해제 및 종료
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return 0;
}

// 메시지 송신 스레드
void *send_msg(void *arg)
{
    SSL *ssl = (SSL*)arg;
    char name_msg[NAME_SIZE + BUF_SIZE];
    
    while (1)
    {
        fgets(msg, BUF_SIZE, stdin);
        
        if (!strcmp(msg, "q\n") || !strcmp(msg, "Q\n"))
        {
            exit(0);
        }

        sprintf(name_msg, "%s %s", name, msg);
        
        // SSL_write를 통해 암호화하여 전송
        if (SSL_write(ssl, name_msg, strlen(name_msg)) <= 0) {
            break;
        }

        // [UI] 내가 입력한 메시지를 터미널에서 지움 (깔끔한 채팅창 유지)
        printf("\033[1A\033[2K"); 
        fflush(stdout);
    }
    return NULL;
}

// 메시지 수신 스레드
void *recv_msg(void *arg)
{
    SSL *ssl = (SSL*)arg;
    char name_msg[NAME_SIZE + BUF_SIZE];
    int str_len;
    
    while (1)
    {
        // SSL_read를 통해 복호화된 메시지 수신
        str_len = SSL_read(ssl, name_msg, BUF_SIZE - 1);
        
        // 6. 연결 종료 감지 및 프로세스 강제 종료 (핵심)
        // str_len <= 0 이면 서버가 연결을 끊은 것임 (차단 포함)
        if (str_len <= 0) 
        {
            printf("%s\n[!] Server Connection Closed (You might be banned).\n", COLOR_RESET);
            // exit(0)을 호출하여 대기 중인 send_msg 스레드까지 즉시 종료시킴
            exit(0); 
        }
            
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