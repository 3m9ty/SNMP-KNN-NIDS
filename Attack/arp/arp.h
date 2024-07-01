#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <netpacket/packet.h>//sockaddrll_sl
#include <net/ethernet.h>

#include <net/if.h>

struct arp_packet
{
	//各項欄位資訊查詢
	//header
	//dest mac  
	unsigned char mac_target[ETH_ALEN];//ETH_ALEN = ethernet address length = 6 octet
	//source mac
	unsigned char mac_source[ETH_ALEN];
	//ethertype
	unsigned short ethertype;
	
	//ARP frame
	//乙太網路類型值0x0001,以16進制數值紀錄
	unsigned short hw_type; 
	
	//sproto_ip通訊協定協議(0x0800)
	unsigned short proto_type;
	
	//mac地址長度(例如乙太網路的實體位址長度為0x16位元組）
	unsigned char mac_addr_len;
	
	//IP長度(通訊協定位址長度)
	unsigned char ip_addr_len;
	
	//定義ARP封包的型態
	//操作碼 0x1表示請求包,0x2表示應答包
	unsigned short operation_code;
	
	//發送方mac
	unsigned char mac_sender[ETH_ALEN];

	//發送方IP
	unsigned char ip_sender[4];
	
	//接收方MAC
	unsigned char mac_receiver[ETH_ALEN];
	
	//接收方IP
	unsigned char ip_receiver[4];
	
	//填充數據(用不到)
	unsigned char padding[18];
	
};





































