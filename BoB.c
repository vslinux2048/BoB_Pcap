#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#define True 1

// void test(void * vpn)
// {
// 	struct iphdr *iph = (struct iphdr *)vpn;
// 	printf("MAC: %s\n", inet_ntoa(iph->saddr));
// }

void * Ipheader(void * v) 
{
	struct iphdr * iph = (struct iphdr *)v;
	printf("IP Version: %d \n", iph->version);
}

int main(int argc, char *argv[])
{
pcap_t *handle;			/* Session handle */
char *dev;			/* 사용자 디바이스 */
char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
struct bpf_program fp;		/* The compiled filter */
char filter_exp[] = "port 80";	/* The filter expression */
bpf_u_int32 mask;		/* Our netmask */
bpf_u_int32 net;		/* Our IP */
struct pcap_pkthdr * header;	/* The header that pcap gives us */
const u_char *packet;		/* The actual packet */
int pat;
struct ether_header * p_a;
int x;



		/* Define the device */
	dev = pcap_lookupdev(errbuf);	/* 네트워크 디바이스명 가져오는 함수 */
	if (dev == NULL) {
		fprintf(stderr, "네트워크 디바이스가 존재하지 않습니다. Error: %s\n", errbuf);
		return(2);
	}
		/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 	/* 네트워크 디바이스에 대한 네트워크번호와 MASK 번호를 되돌려준다. */
	{	
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
		/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);		/* 패킷을 캡처하는 실질적인 역할 */
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
		/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {	 /* 들어 오는 패킷을 필터링 */
	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	return(2);
}
if (pcap_setfilter(handle, &fp) == -1) {
	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	return(2);
}

while(True)
{

	if(pat = pcap_next_ex(handle, &header, &packet))
	{

		struct iphdr * iph = (void*)(packet+sizeof(struct ether_header));
		struct ether_header * ehP = (struct ether_header *)(void*)packet;

		printf("\n\n----------DongDongE!! Packet ----------\n");
		printf("[*]IP Version: %d [*]\n", iph->version);
		printf("[*]Source IP : %s [*]\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
		printf("[*]Destionation IP : %s [*]\n", inet_ntoa(*(struct in_addr *)&iph->daddr));

		printf("[*]Source MAC :");
		for (x=0; x<6; x++)
		{
			printf("%02X", ehP->ether_shost[x]);
		}
		puts("");

		printf("[*]Source Port : %d \n", *(packet+34) + *(packet+35) );
		printf("[*]Destionation Port : %d \n", *(packet+36) + *(packet+37) );
	}

	
}

pcap_close(handle);
return(0);
}