#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <net/if.h>

unsigned char mymac[6] = { 0xf2,0x3c,0x91,0xdb,0xc2,0x98 };
unsigned char myip[4]= { 88,80,187,84};
unsigned char netmask[4]= {255,255,255,0}; 
unsigned char gateway[4]= {88,80,187,1};
unsigned char dest_ip[4]= { 88,80,187,83};
//unsigned char dest_ip[4]= { 147,162,2,100};
unsigned char broadcast[6]={0xff,0xff,0xff,0xff,0xff,0xff};

#define ETH_MTU 1500
int s,i,t;
int sll_len,len;
struct sockaddr_ll sll;
unsigned char l2buf[ETH_MTU];

struct eth_frame {
	unsigned char dest[6];
	unsigned char src[6];
	unsigned short type;
	unsigned char payload[1];
};

struct ip_datagram{
	unsigned char ver_ihl;
	unsigned char tos;
	unsigned short totlen;
	unsigned short id;
	unsigned short flags_offs;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned int src;
	unsigned int dst;
	unsigned char payload[1];
};

unsigned short int checksum( void * ip, int len){
	unsigned int tot=0;
	unsigned short * p;
	int i;
	p = (unsigned short*) ip;

	for (i = 0; i < len / 2 ; i++){
		tot = tot + htons(p[i]);
		if(tot&0x10000) tot=(tot+1)&0xFFFF;	
	}
	if ( i*2 < len){ 
		tot = tot + htons(p[i])&0xFF00;
		if(tot&0x10000) tot=(tot+1)&0xFFFF;	
	}
	return  (0xFFFF-(unsigned short)tot);
}	

void forge_ip(struct ip_datagram * ip, unsigned short int payloadsize,unsigned char protocol, unsigned char * dest  ){
	ip->ver_ihl = 0x45;
	ip->tos = 0;
	ip->totlen=htons(payloadsize + 20);
	ip->id=htons(0x1234);
	ip->flags_offs=0;
	ip->ttl=1;
	ip->proto = protocol;
	ip->checksum = htons(0);
	ip->src = *(unsigned int *)myip;
	ip->dst = *(unsigned int *)dest;
	ip->checksum = htons(checksum(ip,20));
}
struct icmp_packet{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
	unsigned char payload[1];
};

void forge_icmp(struct icmp_packet * icmp,int payloadsize )
{
	icmp->type = 8;
	icmp->code = 0;
	icmp->checksum = htons(0);
	icmp->id = htons(0xABCD);
	icmp->seq = htons(1);
	for(int i=0 ; i < payloadsize; i++) 
		icmp->payload[i]=i%0xFF;	
	icmp->checksum = htons(checksum(icmp,payloadsize+8));

}


struct arp_packet{
	unsigned short htype;
	unsigned short ptype;
	unsigned char hsize;
	unsigned char psize;
	unsigned short op;
	unsigned char hsrc[6];
	unsigned char psrc[4];
	unsigned char hdst[6];
	unsigned char pdst[4];
};

void forge_eth(struct eth_frame * e, unsigned char * dest, unsigned short type)
{
	for(int i=0; i < 6 ; i++) e->dest[i] = dest[i];
	for(int i=0; i < 6 ; i++) e->src[i] = mymac[i];
	e->type = htons(type);
}

void forge_arp_req(struct arp_packet * a, unsigned char * targetip ){
	a->htype = htons ( 1 );
	a->ptype = htons ( 0x0800);
	a->hsize = 6;
	a->psize = 4;
	a->op = htons(1);
	for(int i=0; i < 6 ; i++) a->hsrc[i] = mymac[i];
	for(int i=0; i < 4 ; i++) a->psrc[i] = myip[i];

	for(int i=0; i < 6 ; i++) a->hdst[i] = 0;
	for(int i=0; i < 4 ; i++) a->pdst[i] = targetip[i];

}
void print_buffer(unsigned char * b, int s){

	for(int i=0; i<s; i++){
		if (!(i%4))
			printf("\n");
		printf("%.2X (%.3d) ",b[i],b[i]);
	}
	printf("\n");
}


int resolve_ip(unsigned char* target_ip, unsigned char* target_mac){
	struct eth_frame * eth;
	struct arp_packet * arp;
	unsigned char l2buf[ETH_MTU];
	bzero(&sll,sizeof(struct sockaddr_ll));
	sll.sll_family=AF_PACKET;
	sll.sll_ifindex = if_nametoindex("eth0");
	sll_len=sizeof(struct sockaddr_ll);

	eth = (struct eth_frame *) l2buf;
	arp = (struct arp_packet *) eth->payload;
	forge_eth(eth,broadcast,0x0806);
	forge_arp_req(arp,target_ip);

	print_buffer(l2buf,6+6+2+sizeof(struct arp_packet));
	t = sendto(s, l2buf,14+sizeof(struct arp_packet), 0, (struct sockaddr *) &sll, sll_len); 
	printf("%d  bytes sent\n",t);

	for(int i =0 ; i< 100; i++){
		len = recvfrom(s, l2buf, ETH_MTU, 0, (struct  sockaddr *) & sll, &sll_len);
		if (len == -1 ) {
			perror("recvfrom failed");
			return 1;
		}
		if(eth->type == htons(0x0806) && !memcmp(eth->dest,mymac,6))
			if(arp->op == htons(2) && !memcmp(target_ip,arp->psrc,4)){
				print_buffer(l2buf,6+6+2+sizeof(struct arp_packet));
				memcpy(target_mac, arp->hsrc,6);
				return 0; //success
			}
	}
	return 1; //failed
}

int main(){
	struct eth_frame * eth;
	struct ip_datagram *ip;
	struct icmp_packet *icmp;

	unsigned char dest_mac[6];
	s = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if ( s == -1) {
		perror("Socket Failed");
		return 1;
	}


	eth = (struct eth_frame*) l2buf;
	ip = (struct ip_datagram *) eth->payload;
	icmp = (struct icmp_packet *) ip->payload;

	forge_icmp( icmp, 20 );
	forge_ip( ip, 28, 1,dest_ip);

	if(*(unsigned int*)myip&(*(unsigned int*)netmask ) ==
			*(unsigned int*)dest_ip & (*(unsigned int*)netmask)) 
		resolve_ip(dest_ip,dest_mac);
	else
		resolve_ip(gateway,dest_mac);

	printf("Dest MAC\n");
	print_buffer(dest_mac,6);

	forge_eth(eth,dest_mac,0x0800);
	printf("Outgoing  packet:");
	print_buffer(l2buf,14+20+8+20);

	bzero(&sll,sizeof(struct sockaddr_ll));
	sll.sll_family=AF_PACKET;
	sll.sll_ifindex = if_nametoindex("eth0");
	sll_len=sizeof(struct sockaddr_ll);
	t = sendto(s, l2buf,14+20+8+20, 0, (struct sockaddr *) &sll, sll_len); 

	for(int i =0 ; i< 100; i++){
		len = recvfrom(s, l2buf, ETH_MTU, 0, (struct  sockaddr *) & sll, &sll_len);
		if (len == -1 ) {
			perror("recvfrom failed");
			return 1;
		}

		if (ip->proto == 1){ // if IP includes an ICMP 
			if (icmp->type == 0 && icmp->id == htons(0xABCD) && icmp->seq==htons(1)){
				printf("Echo reply\n");
				print_buffer(l2buf,14+20+8+20);
				return 1;
			}	
			if (icmp->type == 11 && (icmp->code == 0 || icmp->code == 1)) { // time to live exceeded
				printf("Time to live exceeded\n");
				print_buffer(l2buf,14+20+8+20);
				printf("IP address of the node that discarded the packet\n");
				unsigned char* ptr = &(ip->src);
				printf("%.3d.%.3d.%.3d.%.3d\n", *ptr, *(ptr + 1), *(ptr + 2), *(ptr + 3));
				return 1;
			}
		}
	}
}

