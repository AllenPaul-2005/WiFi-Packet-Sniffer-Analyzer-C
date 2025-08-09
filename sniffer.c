/*
    Simple Sniffer with Npcap/WinPcap, prints ethernet, ip, tcp, udp and icmp headers along with data dump in hex
    Updated for GCC/MinGW by Allen’s Helper
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h> // For inet_ntoa and ntohs
#include <pcap.h>     // For packet capture

#pragma comment(lib, "ws2_32.lib") // Winsock
#pragma comment(lib, "wpcap.lib")  // WinPcap/Npcap

// Ethernet Header
typedef struct ethernet_header
{
    unsigned char dest[6];
    unsigned char source[6];
    unsigned short type;
} ETHER_HDR;

// IPv4 Header
typedef struct ip_hdr
{
    unsigned char ip_header_len : 4;
    unsigned char ip_version : 4;
    unsigned char ip_tos;
    unsigned short ip_total_length;
    unsigned short ip_id;
    unsigned short ip_offset;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short ip_checksum;
    unsigned int ip_srcaddr;
    unsigned int ip_destaddr;
} IPV4_HDR;

// UDP Header
typedef struct udp_hdr
{
    unsigned short source_port;
    unsigned short dest_port;
    unsigned short udp_length;
    unsigned short udp_checksum;
} UDP_HDR;

// TCP Header
typedef struct tcp_header
{
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int sequence;
    unsigned int acknowledge;
    unsigned char data_offset : 4;
    unsigned char reserved : 4;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
} TCP_HDR;

// ICMP Header
typedef struct icmp_hdr
{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
} ICMP_HDR;

FILE *logfile;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0;
struct sockaddr_in source, dest;

// Function declarations
void ProcessPacket(const u_char *, int);
void print_ethernet_header(const u_char *);
void PrintIpHeader(const u_char *, int);
void PrintIcmpPacket(const u_char *, int);
void print_udp_packet(const u_char *, int);
void PrintTcpPacket(const u_char *, int);
void PrintData(const u_char *, int);

int main()
{
    pcap_if_t *alldevs, *d;
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0, inum;
    const u_char *pkt_data;
    struct pcap_pkthdr *header;

    logfile = fopen("log.txt", "w");
    if (logfile == NULL)
    {
        printf("Unable to create log.txt file.\n");
        return 1;
    }

    // Retrieve device list
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        return -1;
    }

    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
        {
            printf(" (%s)\n", d->description);
        }
        else
        {
            printf(" (No description available)\n");
        }
    }

    if (i == 0)
    {
        printf("No interfaces found! Exiting.\n");
        return -1;
    }

    printf("Enter the interface number to sniff: ");
    scanf("%d", &inum);

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
        ;

    if ((fp = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 20, NULL, errbuf)) == NULL)
    {
        fprintf(stderr, "\nError opening adapter.\n");
        return -1;
    }

    // Start capture loop
    while (1)
    {
        int res = pcap_next_ex(fp, &header, &pkt_data);
        if (res == 0)
            continue; // Timeout
        if (res == -1 || res == -2)
            break;

        ProcessPacket(pkt_data, header->len);
    }

    pcap_freealldevs(alldevs);
    fclose(logfile);
    return 0;
}

void ProcessPacket(const u_char *Buffer, int Size)
{
    ETHER_HDR *ethhdr = (ETHER_HDR *)Buffer;
    IPV4_HDR *iphdr;

    ++total;

    if (ntohs(ethhdr->type) == 0x0800)
    { // IP Packet
        iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));

        switch (iphdr->ip_protocol)
        {
        case 1:
            icmp++;
            PrintIcmpPacket(Buffer, Size);
            break;
        case 2:
            igmp++;
            break;
        case 6:
            tcp++;
            PrintTcpPacket(Buffer, Size);
            break;
        case 17:
            udp++;
            print_udp_packet(Buffer, Size);
            break;
        default:
            others++;
            break;
        }
    }
    printf("TCP: %d UDP: %d ICMP: %d IGMP: %d Others: %d Total: %d\r", tcp, udp, icmp, igmp, others, total);
}

void print_ethernet_header(const u_char *buffer)
{
    ETHER_HDR *eth = (ETHER_HDR *)buffer;
    fprintf(logfile, "\nEthernet Header\n");
    fprintf(logfile, " |-Destination Address : %02X-%02X-%02X-%02X-%02X-%02X \n", eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5]);
    fprintf(logfile, " |-Source Address      : %02X-%02X-%02X-%02X-%02X-%02X \n", eth->source[0], eth->source[1], eth->source[2], eth->source[3], eth->source[4], eth->source[5]);
    fprintf(logfile, " |-Protocol            : 0x%04x \n", ntohs(eth->type));
}

void PrintIpHeader(const u_char *Buffer, int Size)
{
    int iphdrlen;
    IPV4_HDR *iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
    iphdrlen = iphdr->ip_header_len * 4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iphdr->ip_srcaddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iphdr->ip_destaddr;

    print_ethernet_header(Buffer);

    fprintf(logfile, "\nIP Header\n");
    fprintf(logfile, " |-IP Version        : %d\n", iphdr->ip_version);
    fprintf(logfile, " |-IP Header Length  : %d Bytes\n", iphdrlen);
    fprintf(logfile, " |-Type Of Service   : %d\n", iphdr->ip_tos);
    fprintf(logfile, " |-Total Length      : %d\n", ntohs(iphdr->ip_total_length));
    fprintf(logfile, " |-Identification    : %d\n", ntohs(iphdr->ip_id));
    fprintf(logfile, " |-TTL               : %d\n", iphdr->ip_ttl);
    fprintf(logfile, " |-Protocol          : %d\n", iphdr->ip_protocol);
    fprintf(logfile, " |-Checksum          : %d\n", ntohs(iphdr->ip_checksum));
    fprintf(logfile, " |-Source IP         : %s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile, " |-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
}

void PrintTcpPacket(const u_char *Buffer, int Size)
{
    IPV4_HDR *iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
    int iphdrlen = iphdr->ip_header_len * 4;
    TCP_HDR *tcph = (TCP_HDR *)(Buffer + iphdrlen + sizeof(ETHER_HDR));
    int header_size = sizeof(ETHER_HDR) + iphdrlen + tcph->data_offset * 4;
    int data_size = Size - header_size;

    fprintf(logfile, "\n\n***********************TCP Packet*************************\n");
    PrintIpHeader(Buffer, Size);

    fprintf(logfile, "\nTCP Header\n");
    fprintf(logfile, " |-Source Port      : %u\n", ntohs(tcph->source_port));
    fprintf(logfile, " |-Destination Port : %u\n", ntohs(tcph->dest_port));
    fprintf(logfile, " |-Sequence Number  : %u\n", ntohl(tcph->sequence));
    fprintf(logfile, " |-Acknowledge No   : %u\n", ntohl(tcph->acknowledge));
    fprintf(logfile, " |-Header Length    : %d Bytes\n", tcph->data_offset * 4);
    fprintf(logfile, " |-Window           : %d\n", ntohs(tcph->window));
    fprintf(logfile, " |-Checksum         : %d\n", ntohs(tcph->checksum));
    fprintf(logfile, " |-Urgent Pointer   : %d\n", tcph->urgent_pointer);

    fprintf(logfile, "\nData Payload\n");
    PrintData(Buffer + header_size, data_size);
}

void print_udp_packet(const u_char *Buffer, int Size)
{
    IPV4_HDR *iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
    int iphdrlen = iphdr->ip_header_len * 4;
    UDP_HDR *udph = (UDP_HDR *)(Buffer + iphdrlen + sizeof(ETHER_HDR));
    int header_size = sizeof(ETHER_HDR) + iphdrlen + sizeof(UDP_HDR);
    int data_size = Size - header_size;

    fprintf(logfile, "\n\n***********************UDP Packet*************************\n");
    PrintIpHeader(Buffer, Size);

    fprintf(logfile, "\nUDP Header\n");
    fprintf(logfile, " |-Source Port      : %d\n", ntohs(udph->source_port));
    fprintf(logfile, " |-Destination Port : %d\n", ntohs(udph->dest_port));
    fprintf(logfile, " |-Length           : %d\n", ntohs(udph->udp_length));
    fprintf(logfile, " |-Checksum         : %d\n", ntohs(udph->udp_checksum));

    fprintf(logfile, "\nData Payload\n");
    PrintData(Buffer + header_size, data_size);
}

void PrintIcmpPacket(const u_char *Buffer, int Size)
{
    IPV4_HDR *iphdr = (IPV4_HDR *)(Buffer + sizeof(ETHER_HDR));
    int iphdrlen = iphdr->ip_header_len * 4;
    ICMP_HDR *icmph = (ICMP_HDR *)(Buffer + iphdrlen + sizeof(ETHER_HDR));
    int header_size = sizeof(ETHER_HDR) + iphdrlen + sizeof(ICMP_HDR);
    int data_size = Size - header_size;

    fprintf(logfile, "\n\n***********************ICMP Packet*************************\n");
    PrintIpHeader(Buffer, Size);

    fprintf(logfile, "\nICMP Header\n");
    fprintf(logfile, " |-Type     : %d\n", icmph->type);
    fprintf(logfile, " |-Code     : %d\n", icmph->code);
    fprintf(logfile, " |-Checksum : %d\n", ntohs(icmph->checksum));
    fprintf(logfile, " |-ID       : %d\n", ntohs(icmph->id));
    fprintf(logfile, " |-Sequence : %d\n", ntohs(icmph->seq));

    fprintf(logfile, "\nData Payload\n");
    PrintData(Buffer + header_size, data_size);
}

void PrintData(const u_char *data, int Size)
{
    int i, j;
    unsigned char a, line[17];
    for (i = 0; i < Size; i++)
    {
        a = (data[i] >= 32 && data[i] <= 128) ? (unsigned char)data[i] : '.';
        fprintf(logfile, " %02X", data[i]);
        line[i % 16] = a;
        if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1)
        {
            line[i % 16 + 1] = '\0';
            fprintf(logfile, "         ");
            for (j = strlen((const char *)line); j < 16; j++)
            {
                fprintf(logfile, "   ");
            }
            fprintf(logfile, "%s \n", line);
        }
    }
}
