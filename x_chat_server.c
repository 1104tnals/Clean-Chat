/**
 * Project: Clean-Chat Sentinel (Phase 1)
 * File: chat_server.c
 * Description: 1:N 멀티스레드 TCP 채팅 서버 (기본 뼈대)
 * Author: Clean-Chat Team
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h> // 멀티스레드 사용을 위한 헤더

#define BUF_SIZE 100
#define MAX_CLNT 256

void *handle_clnt(void *arg);
void send_msg(char *msg, int len);
void error_handling(char *msg);

// 공유 자원: 접속한 클라이언트 소켓들을 관리하는 배열과 카운터
int clnt_socks[MAX_CLNT];
int clnt_cnt = 0;

// 동기화 객체: 공유 자원(clnt_socks, clnt_cnt) 접근 시 충돌 방지
pthread_mutex_t mutx;

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

    // Mutex 초기화
    pthread_mutex_init(&mutx, NULL);

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1) error_handling("socket() error");

    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(atoi(argv[1]));

    if (bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
        error_handling("bind() error");

    if (listen(serv_sock, 5) == -1)
        error_handling("listen() error");
    
    printf(">> Clean-Chat Sentinel Server Started...\n");

    while (1)
    {
        clnt_adr_sz = sizeof(clnt_adr);
        // 클라이언트 접속 대기 (Blocking)
        clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);

        // [Critical Section Start] 새로운 소켓을 배열에 등록
        pthread_mutex_lock(&mutx);
        clnt_socks[clnt_cnt++] = clnt_sock;
        pthread_mutex_unlock(&mutx);
        // [Critical Section End]

        // 해당 클라이언트를 전담할 스레드 생성
        pthread_create(&t_id, NULL, handle_clnt, (void*)&clnt_sock);
        // 스레드가 종료되면 자동으로 메모리 소멸 (Detached state)
        pthread_detach(t_id);
        
        printf("Connected client IP: %s \n", inet_ntoa(clnt_adr.sin_addr));
    }

    close(serv_sock);
    return 0;
}

// 클라이언트 전담 스레드 실행 함수
void *handle_clnt(void *arg)
{
    int clnt_sock = *((int*)arg);
    int str_len = 0;
    char msg[BUF_SIZE];

    // 클라이언트가 보낸 메시지를 계속해서 읽음
    while ((str_len = read(clnt_sock, msg, sizeof(msg))) != 0)
        send_msg(msg, str_len); // 읽은 메시지를 모든 클라이언트에게 전송 (Broadcast)

    // 반복문을 빠져나왔다는 것은 클라이언트가 연결을 끊었다는 의미
    
    // [Critical Section Start] 접속 끊긴 클라이언트 제거 로직
    pthread_mutex_lock(&mutx);
    for (int i = 0; i < clnt_cnt; i++)
    {
        if (clnt_sock == clnt_socks[i])
        {
            // 현재 끊긴 클라이언트 자리에 맨 뒤의 클라이언트를 당기거나
            // 뒤의 요소들을 한 칸씩 앞으로 이동시킴
            while (i++ < clnt_cnt - 1)
                clnt_socks[i] = clnt_socks[i + 1];
            break;
        }
    }
    clnt_cnt--;
    pthread_mutex_unlock(&mutx);
    // [Critical Section End]

    close(clnt_sock);
    return NULL;
}

// 연결된 모든 클라이언트에게 메시지 전송 (Broadcast)
void send_msg(char *msg, int len)
{
    pthread_mutex_lock(&mutx);
    for (int i = 0; i < clnt_cnt; i++)
        write(clnt_socks[i], msg, len);
    pthread_mutex_unlock(&mutx);
}

void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}