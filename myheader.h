#ifndef MYHEADER_H
#define MYHEADER_H

// Ethernet 헤더 (고정 14바이트) 
struct ethheader {
    u_char  ether_dhost[6]; //목적지 MAC 주소 
    u_char  ether_shost[6]; // 출발지 MAC 주소 
    u_short ether_type;     //상위 프로토콜 종류 
};

// IP 헤더 
struct ipheader {
    unsigned char      iph_ihl:4,   // IP 헤더 길이 (4바이트 단위) 
                       iph_ver:4;   // IP 버전 
    unsigned char      iph_tos;     // 서비스 종류 
    unsigned short int iph_len;     // 전체 길이 (헤더 + 데이터) 
    unsigned short int iph_ident;   // 식별자 
    unsigned short int iph_flag:3,  // 플래그 
                       iph_offset:13;
    unsigned char      iph_ttl;     // TTL 
    unsigned char      iph_protocol;// 상위 프로토콜 (6 = TCP) 
    unsigned short int iph_chksum;  // 체크섬 
    struct in_addr     iph_sourceip;// 출발지 IP 
    struct in_addr     iph_destip;  // 목적지 IP 
};

// TCP 헤더 
struct tcpheader {
    u_short tcp_sport;   // 출발지 포트
    u_short tcp_dport;   // 목적지 포트 
    u_int   tcp_seq;     // 시퀀스 번호 
    u_int   tcp_ack;     // 확인 응답 번호 
    u_char  tcp_offx2;   // 상위 4비트 = 데이터 오프셋(=TCP 헤더 길이) 
#define TH_OFF(th)  (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    u_short tcp_win;     // 윈도우 크기 
    u_short tcp_sum;     // 체크섬 
    u_short tcp_urp;     // 긴급 포인터 
};

#endif
