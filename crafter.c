#include <arpa/inet.h>
#include "crafter.h"
#include <ctype.h>
#include <getopt.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*static const char* param_config_file = "PARAM_CONFIG";
static const int num_params = 13;
enum OptionField
{
    NAME,
    HAS_ARG,
    VAL
};*/

int main(int argc, char** argv)
{
    const int IP_ADDRESS_LEN = 23; // includes port number and ip address
    const int NUM_TCP_FLAGS = 6;
    const int TCP_SEQ_ACK_LEN = 10;
    const int TCP_WIN_SIZE_LEN = 5;
    const int IP_TTL_LEN = 3;
    const int ICMP_TYPE_LEN = 3;
    const int ICMP_CODE_LEN = 2;
    static int udp_flag = 0;
    static int tcp_flag = 0;
    static int icmp_flag = 0;

    int c;//, udp_flag = 0, tcp_flag = 0, icmp_flag = 0;

    //generate_long_options(param_config_file, &udp_flag, &tcp_flag, &icmp_flag, long_options);
    static struct option long_options[] = //generate_long_options(param_config_file,
    //        &udp_flag, &tcp_flag, &icmp_flag);
    {
        {"udp", no_argument, &udp_flag, 1},
        {"tcp", no_argument, &tcp_flag, 1},
        {"icmp", no_argument, &icmp_flag, 1},
        {"src", required_argument, 0, 's'},
        {"dest", required_argument, 0, 'd'},
        {"tcpflag", required_argument, 0, 'l'},
        {"seqnum", required_argument, 0, 'e'},
        {"acknum", required_argument, 0, 'k'},
        {"window", required_argument, 0, 'w'},
        {"ipttl", required_argument, 0, 't'},
        {"icmptype", required_argument, 0, 'y'},
        {"icmpcode", required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    int option_index = 0;

    // TODO: set these to default values from file
    // Add 1 to the lengths for the null char
    char src_address[IP_ADDRESS_LEN + 1], dst_address[IP_ADDRESS_LEN + 1], tcp_flags[NUM_TCP_FLAGS + 1];
    char tcp_seq_num[TCP_SEQ_ACK_LEN + 1], tcp_ack_num[TCP_SEQ_ACK_LEN + 1], tcp_win_size[TCP_WIN_SIZE_LEN + 1];
    char ip_ttl[IP_TTL_LEN + 1], icmp_type[ICMP_TYPE_LEN + 1], icmp_code[ICMP_CODE_LEN + 1];

    while (1)
    {
        c = getopt_long(argc, argv, "utis:d:l:e:k:w:t:y:c:", long_options, &option_index);
        switch (c)
        {
            case 0:
                break;

            case 's':
                strcpy(src_address, optarg);
                break;

            case 'd':
                strcpy(dst_address, optarg);
                break;

            case 'l':
                strcpy(tcp_flags, optarg);
                break;

            case 'e':
                strcpy(tcp_seq_num, optarg);
                break;

            case 'k':
                strcpy(tcp_ack_num, optarg);
                break;

            case 'w':
                strcpy(tcp_win_size, optarg);
                break;

            case 't':
                strcpy(ip_ttl, optarg);
                break;

            case 'y':
                strcpy(icmp_type, optarg);
                break;

            case 'c':
                strcpy(icmp_code, optarg);
                break;

            default:
                printf("Invalid argument");
                abort();
        }
    }

    char packet[4096];
    memset(packet, 0, 4096);
    char* src_addr, *src_port, *dst_addr, *dst_port;
    parseAddrPort(src_address, src_addr, src_port);
    parseAddrPort(dst_address, dst_addr, dst_port);

    struct iphdr* ip_header = (struct iphdr*) packet;
    generate_ip_header(ip_header, src_addr, dst_addr, ip_ttl);

    if (udp_flag)
    {
        ip_header->tot_len = sizeof(struct udphdr) + sizeof(struct iphdr);
        generate_udp_packet(packet, src_port, dst_port);
    }
    else if (tcp_flag)
    {
        ip_header->tot_len = sizeof(struct tcphdr) + sizeof(struct iphdr);
        generate_tcp_packet(packet, src_port, dst_port, tcp_flags, tcp_seq_num,
                tcp_ack_num, tcp_win_size);
    }
    else if (icmp_flag)
    {
        generate_icmp_packet(packet, icmp_type, icmp_code);
    }

    int s = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

    return 0;
}

void generate_ip_header(struct iphdr* ip_header, const char* src_addr,
        const char* dst_addr, const char* ip_ttl)
{
    struct in_addr* src;
    struct in_addr* dst;
    inet_aton(src_addr, src);
    inet_aton(dst_addr, dst);

    ip_header->id = 0;
    ip_header->frag_off = 0;
    ip_header->ttl = strtol(ip_ttl, NULL, 10);
    ip_header->protocol = IPPROTO_UDP;
    ip_header->check = 0;
    ip_header->saddr = src->s_addr;
    ip_header->daddr = dst->s_addr;
}

void generate_udp_packet(char* packet, const char* src_port,
        const char* dst_port)
{
    struct udphdr* udp_header = (struct udphdr*) (packet + sizeof(struct iphdr));
    udp_header->source = strtol(src_port, NULL, 10);
    udp_header->dest = strtol(dst_port, NULL, 10);
    udp_header->len = sizeof(struct udphdr);
}

void generate_tcp_packet(char* packet, const char* src_port,
        const char* dst_port, const char* tcp_flags, const char* tcp_seq_num,
        const char* tcp_ack_num, const char* tcp_win_size)
{
    int i, flag_len;
    struct tcphdr* tcp_header = (struct tcphdr*) (packet + sizeof(struct iphdr));
    tcp_header->source = strtol(src_port, NULL, 10);
    tcp_header->dest = strtol(dst_port, NULL, 10);
    tcp_header->seq = strtol(tcp_seq_num, NULL, 10);
    tcp_header->ack_seq = strtol(tcp_ack_num, NULL, 10);
    tcp_header->doff = 5;
    tcp_header->urg = 0;
    tcp_header->ack = 0;
    tcp_header->psh = 0;
    tcp_header->rst = 0;
    tcp_header->syn = 0;
    tcp_header->fin = 0;
    tcp_header->window = strtol(tcp_win_size, NULL, 10);
    tcp_header->urg_ptr = 0;

    flag_len = strlen(tcp_flags);
    for (i = 0; i < flag_len; i++)
    {
        switch (toupper(tcp_flags[i]))
        {
            case 'U':
                tcp_header->urg = 1;
                break;

            case 'A':
                tcp_header->ack = 1;
                break;

            case 'P':
                tcp_header->psh = 1;
                break;

            case 'R':
                tcp_header->rst = 1;
                break;

            case 'S':
                tcp_header->syn = 1;
                break;

            case 'F':
                tcp_header->fin = 1;
                break;

            default:
                printf("Invalid TCP flag");
                abort();
        }
    }

    // TODO: tcp_header->check = checksum();
}

void parseAddrPort(const char* addr_port, char* addr, char* port)
{
    char** target = &addr;
    int i, j = 0, addr_port_len = strlen(addr_port);

    for (i = 0; i < addr_port_len; i++)
    {
        if (addr_port[i] == ':')
        {
            target = &port;
            j = 0;
        }
        else
        {
            (*target)[j++] = addr_port[i];
        }
    }
}

// length is in bytes, calculates checksum based on 16 bit words
unsigned short checksum(unsigned short* data, int len)
{
    int i, two_byte_words = len / 2;
    long sum = 0;

    for (i = 0; i < two_byte_words; i++)
    {
        sum += data[i];
    }

    if (len % 2 == 1)
    {
        sum += (data[i] & 0xFF00);
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~((unsigned short) sum);
}
