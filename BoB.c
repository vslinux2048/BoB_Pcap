#include <pcap.h>
#include <stdio.h>
#define True 1

int main(int argc, char *argv[])
{
		pcap_t *handle;			/* Session handle */
		char *dev;			/* 사용자 디바이스 */
		char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
		struct bpf_program fp;		/* The compiled filter */
		char filter_exp[] = "port 80";	/* The filter expression */
		bpf_u_int32 mask;		/* Our netmask */
		bpf_u_int32 net;		/* Our IP */
		struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */


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

	/* Grab a packet */
		packet = pcap_next(handle, &header);

		/* Print its length */
		printf("Jacked a packet with length of [%d]\n", header.len);
		// printf("%d dwadd\n", mask);


		/* And close the session */
	}

	pcap_close(handle);
	return(0);
}


