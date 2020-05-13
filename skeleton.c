#include <stdio.h>
#include <pcap.h> // PCAP 라이브러리 가져오기
#include <arpa/inet.h> // inet_ntoa 등 함수 포함
#include <netinet/in.h> // in_addr 등 구조체 포함

pcap_t *handle; // 핸들러
char *dev = "eth0"; // 자신의 네트워크 장비
char errbuf[PCAP_ERRBUF_SIZE]; // 오류 메시지를 저장하는 버퍼
struct bpf_program fp; // 필터 구조체
char *filter_exp = "port 80"; // 필터 표현식
bpf_u_int32 mask; // 서브넷 마스크
bpf_u_int32 net; // 아이피 주소
struct pcap_pkthdr *header; // 패킷 관련 정보
const u_char *packet; // 실제 패킷
struct in_addr addr; // 주소 정보

#define ETHER_ADDR_LEN 6

struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; // 목적지 MAC 주소 6bytes
        u_char ether_shost[ETHER_ADDR_LEN]; // 출발지 MAC 주소 6bytes
        u_short ether_type;// ethernet type: ipv4:0x0800 arp:0x0806 //2bytes
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

struct sniff_ip {
        u_char ip_vhl; //version <<4 | header length>>2 1byte
        u_char ip_tos; //typeofservice 1byte
        u_short ip_len; //2bytes
        u_short ip_id; //2bytes
        u_short ip_off; //2bytes
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char ip_ttl; //1byte
        u_char ip_p; // IP 프로토콜 유형 //1byte
        u_short ip_sum; //2bytes
        struct in_addr ip_src; // 출발지 IP 주소 4bytes
        struct in_addr ip_dst; // 목적지 IP 주소 4bytes
};

typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport; // 출발지 TCP 주소
        u_short th_dport; // 목적지 TCP 주소
        tcp_seq th_seq;
        tcp_seq th_ack;
        u_char th_offx2;
        #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;
        u_short th_sum;
        u_short th_urp;
};

#define SIZE_ETHERNET 14

struct sniff_ethernet *ethernet; // 이더넷 헤더
struct sniff_ip *ip; // IP 헤더
struct sniff_tcp *tcp; // TCP 혜더
struct sniff_tcp *tcp_dummy;
char *payload; // 페이로드

u_int size_ip;
u_int size_tcp;

void parsing() {
        struct sniff_tcp dummy;
	printf("------------------------------------------------------\n");
        int i, payload_len;
        ethernet = (struct sniff_ethernet*)(packet);
        printf("MAC 출발지 주소 :");
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_shost[i]);
        }
        printf("\nMAC 목적지 주소 :");
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_dhost[i]);
        }
        printf("\nMAC 목적지 주소 :");
        for(i = 0; i < ETHER_ADDR_LEN; i++) {
                printf("%02x ", ethernet->ether_dhost[i]);
        }
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        printf("\nIP 출발지 주소: %s\n", inet_ntoa(ip->ip_src));
        printf("IP 목적지 주소: %s\n", inet_ntoa(ip->ip_dst));
        
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        tcp_dummy=(struct sniff_tcp*)malloc(sizeof(dummy));

	memcpy(tcp_dummy,tcp,sizeof(tcp));
	tcp_dummy->th_seq=htonl(00000000);
	memcpy(tcp, tcp_dummy, sizeof(tcp));
	size_tcp = TH_OFF(tcp)*4;
        printf("출발지 포트: %d\n", ntohs(tcp->th_sport));
        printf("목적지 포트: %d\n", ntohs(tcp->th_dport));
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        payload_len = ntohs(ip->ip_len) - (size_ip + size_tcp);
        if(payload_len == 0) printf("페이로드 데이터가 없습니다.");
        else {
                printf("< 페이로드 데이터 >\n");
                for(int i = 1; i < payload_len; i++) {
                        printf("%02x ", payload[i - 1]);
                        if(i % 8 == 0) printf("  ");
                        if(i % 16 == 0) printf("\n");
                }
        }
        printf("\n------------------------------------------------------\n");
}

int main(void) {
        //printf("Eth headersize: %d\tTcp headersize: %d\tIP headersize: %d\n",sizeof(struct sniff_ethernet),sizeof(struct sniff_tcp),sizeof(struct sniff_ip));
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
                printf("네트워크 장치를 찾을 수 없습니다.\n");
                return 0;
        }
        printf("나의 네트워크 장치: %s\n", dev);
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                printf("장치의 주소를 찾을 수 없습니다.\n");
                return 0;
        }
        addr.s_addr = net;
        printf("나의 IP주소: %s\n", inet_ntoa(addr));
        addr.s_addr = mask;
        printf("나의 서브넷 마스크: %s\n", inet_ntoa(addr));
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
                printf("장치를 열 수 없습니다.\n");
                return 0;
        }
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                printf("필터를 적용할 수 없습니다.\n");
                return 0;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
                printf("필터를 세팅할 수 없습니다.\n");
                return 0;
        }
        printf("패킷을 감지합니다.\n");
        while(pcap_next_ex(handle, &header, &packet) == 1) {
                parsing();
        }
	return 0;
}