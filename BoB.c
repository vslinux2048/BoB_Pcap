#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define ETHER_ADR_LEN 6
#define True 1			/* while */

/* Ether Header Structure */
struct ether_header
{
	unsigned char ether_shost[ETHER_ADR_LEN];		// S_MAC
	unsigned char ether_dhost[ETHER_ADR_LEN];		// D_MAC
	unsigned short ether_type;				
};

#define  ETHERTYPE_IP     	0x0800   /* IP Protocol */
#define  ETHERTYPE_ARP 		0x0806   /* Address Resolution Protocol */
#define  ETHERTYPE_REVARP	0x8035   /* reverse Address Resolution Protocol */

// 4 bytes IP address
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

// 20 bytes IP Header
typedef struct ip_header
{
	u_char ip_leng:4; 
	u_char  ip_version:4;
	u_char tos; // Type of service 
	u_short tlen; // Total length 
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	ip_address saddr; // Source address
	ip_address daddr; // Destination address
	u_int op_pad; // Option + Padding
}ip_header;

 int main(int argc, char *argv[])
 {
	pcap_t *handle;			/* Session handle */
	char *dev;			/* 사용자 디바이스 */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	struct pcap_pkthdr * header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
 	int x;


		/* Define the device */
	dev = pcap_lookupdev(errbuf);	/* 네트워크 디바이스명 가져오는 함수 */
 	if (dev == NULL) {
 		fprintf(stderr, "네트워크 디바이스가 존재하지 않습니다. Error: %s\n", errbuf);
 		return(2);
 	}

 	dev = argv[1];

		/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);		/* 패킷을 캡처하는 실질적인 역할 */
 	if (handle == NULL) {
 		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
 		return(2);
 	}

 	while(True)
 	{
	/* 캡처한 패킷 데이터를 가져온다. */
 		if(pcap_next_ex(handle, &header, &packet))
 		{
 			struct ether_header * eth = (struct ether_header *)(void*)packet;
 			struct ip_header * ih = (ip_header *)(packet + 14);
 			// printf("S_IP : %d %d %d %d \n\n\n", ih->saddr[0], ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
 			printf("\n\n----------\tDongDongE!! Packet \t----------\n");
 			printf("[*] --- Source MAC: ");
 			for (x = 0; x < 6; x++) {

 				printf("%02X", eth->ether_shost[x]);
 				if(x == 5)
 					break;
 				else
 					printf(":");
 			}
 			puts("");
 			printf("[*] --- Destination MAC: ");
 			for (x = 0; x < 6; x++) {

 				printf("%02X", eth->ether_dhost[x]);
 				if(x == 5)
 					break;
 				else
 					printf(":");
 			}
 			printf("Source IP: %d.%d.%d.%d\n",packet[26],packet[27],packet[28],packet[29]);
 			puts("");

		// printf("[*] IP Version: %d \t[*]\n", iph->version);  // IPv4
		// 									/* inet_ntoa type 정의를 안하면 에러가 발생함으로...*/
		// printf("[*] Source IP : %s \t[*]\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
		// printf("[*] Destionation IP : %s [*]\n", inet_ntoa(*(struct in_addr *)&iph->daddr));

		// printf("[*] Source MAC :");
		// for (x=0; x<6; x++) /* */
		// {
		// 	printf("%02X", ehP->ether_shost[x]);
		// }
		// puts("");

		// // printf("[*] Source Port : %d [*]\n", *(packet+34) + *(packet+35) );
		// printf("[*] Source Port : %d [*]\n", packet[34] + packet[35]);
		// printf("[*] Destionation Port : %d [*]\n", packet[36] + packet[37] );

		// ASCII_DATA(packet, header->caplen);
 		}



 	}

 	pcap_close(handle);
 	return(0);
 }