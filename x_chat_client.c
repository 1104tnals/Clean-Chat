/**
 * Project: Clean-Chat Sentinel (Phase 1)
 * File: chat_client.c
 * Description: 송신/수신 스레드가 분리된 TCP 클라이언트
 * Author: Clean-Chat Team
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

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

    if (argc != 4) {
        printf("Usage : %s <IP> <port> <name>\n", argv[0]);
        exit(1);
    }

    sprintf(name, "[%s]", argv[3]); // 사용자 이름 설정

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) error_handling("socket() error");

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
        error_handling("connect() error");

    printf(">> Connected to Clean-Chat Server!\n");

    // 송신 스레드와 수신 스레드 생성
    pthread_create(&snd_thread, NULL, send_msg, (void*)&sock);
    pthread_create(&rcv_thread, NULL, recv_msg, (void*)&sock);

    // 스레드가 종료될 때까지 대기
    pthread_join(snd_thread, &thread_return);
    pthread_join(rcv_thread, &thread_return);

    close(sock);
    return 0;
}

// chat_client.c 의 send_msg 함수 수정본

void *send_msg(void *arg)
{
    int sock = *((int*)arg);
    char name_msg[NAME_SIZE + BUF_SIZE];
    
    while (1)
    {
        fgets(msg, BUF_SIZE, stdin);
        
        if (!strcmp(msg, "q\n") || !strcmp(msg, "Q\n"))
        {
            close(sock);
            exit(0);
        }

        // 1. 메시지 전송
        sprintf(name_msg, "%s %s", name, msg);
        write(sock, name_msg, strlen(name_msg));

        // 2. [UI 트릭] 방금 내가 입력한 줄을 지운다!
        // \033[1A : 커서를 한 줄 위로 올림
        // \033[2K : 그 줄을 깨끗하게 지움
        // fflush(stdout) : 버퍼를 비워서 즉시 반영
        printf("\033[1A\033[2K"); 
        fflush(stdout);
    }
    return NULL;
}

// 메시지 수신 담당 스레드
void *recv_msg(void *arg)
{
    int sock = *((int*)arg);
    char name_msg[NAME_SIZE + BUF_SIZE];
    int str_len;
    
    while (1)
    {
        str_len = read(sock, name_msg, BUF_SIZE - 1);
        if (str_len == -1)
            return (void*)-1;
        name_msg[str_len] = 0; // 문자열 끝에 null 문자 추가
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