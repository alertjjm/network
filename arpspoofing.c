#include <stdio.h>
#include<stdlib.h>
#include<memory.h>
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
struct in_addr taddr;
u_char mymac[6]={0,12,41,51,19,211};
u_char tmac[6];
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
struct arp_header
{
    u_short hrd_type;//2 ethernet:1
    u_short proto_type;//4 upper protocol:0800
    u_char hrd_len;//5  mac legth:6
    u_char proto_len;//6 ip protocol length:4
    uint16_t oper;//8 arpreq: 0001 reply:0002 rarpreq: 0003 rarpreply: 0004
    uint8_t s_mac[6]; //14
    uint8_t s_ip[4]; // 18
    uint8_t t_mac[6]; //24
    uint8_t t_ip[4]; // 28
};
#define SIZE_ARP 28
struct sniff_arp* arppck;
struct sniff_ethernet *ethernet; // 이더넷 헤더
struct sniff_ip *ip; // IP 헤더
struct sniff_tcp *tcp; // TCP 혜더
struct sniff_tcp *tcp_dummy;
char *payload; // 페이로드

u_int size_ip;
u_int size_tcp;
void getmac(struct in_addr targetip){
        u_char* arpsend;
        arpsend=malloc(sizeof(u_char)*(SIZE_ETHERNET+SIZE_ARP));
        memset(arpsend,0,sizeof(u_char)*(SIZE_ETHERNET+SIZE_ARP));
        struct sniff_ethernet* ethpckt=malloc(sizeof(struct sniff_ethernet));
        struct arp_header* arppckt=(struct arp_header*)(arpsend+SIZE_ETHERNET);

        for(int i=0; i<6; i++)
                ethpckt->ether_dhost[i]=0xFF;
        memcpy(ethpckt->ether_shost,mymac,6);
        ethpckt->ether_type=htons(0x0806);
        arppckt->hrd_type=htons(0x0001);
        arppckt->proto_type=htons(0x0800);
        arppckt->hrd_len=0x06;        
        arppckt->proto_len=0x04;
        arppckt->oper=htons(0x0001);
        memcpy(arppckt->s_mac,mymac,6);
        memcpy(&(arppckt->s_ip),&addr,4);
        for(int i=0; i<6; i++)
                arppckt->t_mac[i]=0x0;
        memcpy(&(arppckt->t_ip),&targetip,4);
        memcpy(arpsend,ethpckt,sizeof(struct sniff_ethernet));
        struct pcap_pkthdr* head;

        while(1){
                pcap_sendpacket(handle, arpsend, SIZE_ETHERNET+ SIZE_ARP);
                int a=pcap_next_ex(handle, &head,&packet);
                struct sniff_ethernet* geteth=(struct sniff_ethernet*)packet;
                struct arp_header* getarp=(struct arp_header*)(packet+SIZE_ETHERNET);
                if(ntohs(geteth->ether_type)==0x0806&&memcmp(&(getarp->s_ip),&targetip,4)==0){
                        memcpy(tmac,geteth->ether_shost,6);
                        break;
                }
                sleep(1);
        }
        for(int i=0; i<6; i++)
        printf("%x ",tmac[i]);
        printf("\n");
}
/*
void send_arp(struct in_addr senderip, struct in_addr targetip, u_char senderMAC[ETHER_ADDR_LEN],u_char targetMAC[ETHER_ADDR_LEN]){
        packet=malloc(sizeof(const u_char)*(SIZE_ETHERNET+SIZE_ARP));
        struct sniff_ethernet* ethpckt=malloc(sizeof(struct sniff_ethernet));
        struct arp_header* arppckt=malloc(sizeof(struct arp_header));
        memcpy(ethpckt->ether_dhost,targetMAC,6);
        memcpy(ethpckt->ether_shost,senderMAC,6);
        ethpckt->ether_type=htons(0x0806);
        arppckt->hrd_type=htons(0x0001);
        arppckt->proto_len=0x06;
        arppckt->oper=0x04;
        memcpy(arppckt->s_mac,senderMAC,6);
        memcpy(&(arppckt->s_ip),&senderip,4);
        memset(arppckt->t_mac,0,6);
        //memcpy(&(arppckt->t_ip),&)
        
        /*
  struct arp_header
{
    u_short hrd_type;//2 ethernet:1
    u_short proto_type;//4 upper protocol:0800
    u_char hrd_len;//5  mac legth:6
    u_char proto_len;//6 ip protocol length:4
    u_short oper;//8 arpreq: 0001 reply:0002 rarpreq: 0003 rarpreply: 0004
    u_char s_mac[6]; //14
    struct in_addr s_ip; // 18
    u_char t_mac[6]; //24
    struct in_addr t_ip; // 28
};
        
}
*/
int main(void) {
        //printf("Eth headersize: %d\tTcp headersize: %d\tIP headersize: %d\n",sizeof(struct sniff_ethernet),sizeof(struct sniff_tcp),sizeof(struct sniff_ip));
        char targetip[20];
        char myipip[20];
        struct in_addr targetaddr;
        printf("Target ip:");
        gets(targetip);
        printf("my ip:");
        gets(myipip);
        targetaddr.s_addr=inet_addr(targetip);
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
        addr.s_addr = inet_addr(myipip);
        printf("나의 IP주소: %s\n", inet_ntoa(addr));
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
                printf("장치를 열 수 없습니다.\n");
                return 0;
        }
        getmac(targetaddr);
	return 0;
}