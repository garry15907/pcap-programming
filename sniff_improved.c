#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "myheader.h"


void print_mac(u_char *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
}

// pcap_loop가 패킷을 하나 잡을 때마다 호출하는 콜백 함수 
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    // 1계층: Ethernet 
    struct ethheader *eth = (struct ethheader *)packet;

    // IP 패킷(0x0800)이 아니면 무시
    if (ntohs(eth->ether_type) != 0x0800) return;

    // 2계층: IP        
    struct ipheader *ip = (struct ipheader *)
                          (packet + sizeof(struct ethheader));

    //TCP만 처리, 그 외(UDP/ICMP 등)는 무시 
    if (ip->iph_protocol != IPPROTO_TCP) return;

    // IP 헤더의 실제 길이(바이트) = iph_ihl * 4      
    int ip_header_len = ip->iph_ihl * 4;

    // 3계층: TCP 
    struct tcpheader *tcp = (struct tcpheader *)
                            (packet + sizeof(struct ethheader) + ip_header_len);

    // TCP 헤더의 실제 길이(바이트) = 데이터 오프셋 * 4 
    int tcp_header_len = TH_OFF(tcp) * 4;

    //계층별 정보 출력 
    printf("========== TCP Packet ==========\n");

    
    printf("[Ethernet] 출발지 MAC 주소: ");  print_mac(eth->ether_shost); printf("\n");
    printf("           도착지 MAC : ");  print_mac(eth->ether_dhost); printf("\n");

   
    printf("[IP]       출발지 IP 주소  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("           도착지 포트 IP주소  : %s\n", inet_ntoa(ip->iph_destip));

    
    printf("[TCP]      출발지 포트 번호: %d\n", ntohs(tcp->tcp_sport));
    printf("           도착지 포트 번호: %d\n", ntohs(tcp->tcp_dport));

    // 4계층: HTTP(페이로드)      
    int header_total = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    const u_char *payload = packet + header_total;

    // 페이로드 길이 = 전체 패킷 길이 - 모든 헤더 길이
    int payload_len = header->caplen - header_total;

    if (payload_len > 0) {
        printf("[HTTP]     Message (%d bytes):\n", payload_len);
        // 페이로드를 문자로 출력 (출력 가능한 문자만, 나머지는 '.')
        for (int i = 0; i < payload_len; i++) {
            u_char c = payload[i];
            if ((c >= 32 && c <= 126) || c == '\n' || c == '\r')
                printf("%c", c);
            else
                printf(".");
        }
        printf("\n");
    } else {
        printf("[HTTP]     Message : (페이로드 없음)\n");
    }
    printf("================================\n\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    // TCP만 캡처하도록 BPF 필터를 tcp로 설정 
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    //NIC에서 라이브 캡처 세션 열기
       
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "장치 열기 실패: %s\n", errbuf);
        return 2;
    }

    //필터 컴파일 및 적용 
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        pcap_perror(handle, "필터 컴파일 오류");
        return 2;
    }
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "필터 적용 오류");
        return 2;
    }

    //패킷 캡처 루프 (잡을 때마다 got_packet 호출) 
    printf("TCP 패킷 캡처 시작\n");
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
