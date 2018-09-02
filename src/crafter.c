#include <arpa/inet.h>
#include "crafter.h"
#include <ctype.h>
#include <errno.h>
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

// struct for TCP pseudoheader
struct tcppshdr
{
    u_int32_t src;
    u_int32_t dst;
    u_int16_t proto;
    u_int16_t len;
};

int main(int argc, char** argv)
{
    // Add 1 to the lengths for the null char
    const int IP_ADDRESS_LEN = 23 + 1; // includes port number and ip address
    const int NUM_TCP_FLAGS = 6 + 1;
    const int TCP_SEQ_ACK_LEN = 10 + 1;
    const int TCP_WIN_SIZE_LEN = 5 + 1;
    const int IP_TTL_LEN = 3 + 1;
    const int ICMP_TYPE_LEN = 3 + 1;
    const int ICMP_CODE_LEN = 2 + 1;
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
        {"tcpflag", required_argument, 0, 'a'},
        {"seqnum", required_argument, 0, 'e'},
        {"acknum", required_argument, 0, 'k'},
        {"window", required_argument, 0, 'w'},
        {"ipttl", required_argument, 0, 'l'},
        {"icmptype", required_argument, 0, 'y'},
        {"icmpcode", required_argument, 0, 'c'},
        {0, 0, 0, 0}
    };

    int option_index = 0;

    // TODO: set these to default values from file
    char src_address[22] = "192.168.0.0:10000";
    char dst_address[22] = "127.0.0.1:8000";
    char tcp_flags[7] = "S";
    char tcp_seq_num[11] = "1";
    char tcp_ack_num[11] = "1";
    char tcp_win_size[6] = "1";
    char ip_ttl[4] = "255";
    char icmp_type[4];
    char icmp_code[3];

    while (1)
    {
        c = getopt_long(argc, argv, "utis:d:a:e:k:w:l:y:c:", long_options, &option_index);
        if (c == -1)
        {
            // detect end of options
            break;
        }

        switch (c)
        {
            case 0:
                break;

            case 'u':
                udp_flag = 1;
                break;

            case 't':
                tcp_flag = 1;
                break;

            case 'i':
                icmp_flag = 1;
                break;

            case 's':
                strcpy(src_address, optarg);
                break;

            case 'd':
                strcpy(dst_address, optarg);
                break;

            case 'a':
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

            case 'l':
                strcpy(ip_ttl, optarg);
                break;

            case 'y':
                strcpy(icmp_type, optarg);
                break;

            case 'c':
                strcpy(icmp_code, optarg);
                break;

            case '?':
                break;

            default:
                printf("Invalid argument\n");
                abort();
        }
    }

    char packet[4096];
    memset(packet, 0, 4096);
    char src_addr[16], src_port[6], dst_addr[16], dst_port[6];
    parseAddrPort(src_address, src_addr, src_port);
    parseAddrPort(dst_address, dst_addr, dst_port);
    struct sockaddr_in sock_dest;

    struct iphdr* ip_header = (struct iphdr*) packet;
    sock_dest.sin_addr.s_addr = generate_ip_header(ip_header, src_addr,
            dst_addr, ip_ttl);
    sock_dest.sin_port = htons(atoi(dst_port));
    sock_dest.sin_family = AF_INET;

    if (udp_flag)
    {
        ip_header->tot_len = sizeof(struct udphdr) + sizeof(struct iphdr);
        ip_header->protocol = IPPROTO_UDP;
        generate_udp_packet(packet, src_port, dst_port);
        ip_header->check = checksum((u_int16_t*) packet,
                sizeof(struct udphdr) + sizeof(struct iphdr));
    }
    else if (tcp_flag)
    {
        printf("tcp\n");
        ip_header->tot_len = sizeof(struct tcphdr) + sizeof(struct iphdr);
        ip_header->protocol = IPPROTO_TCP;
        generate_tcp_packet(packet, src_port, dst_port, tcp_flags, tcp_seq_num,
                tcp_ack_num, tcp_win_size);
        ip_header->check = checksum((u_int16_t*) packet,
                sizeof(struct tcphdr) + sizeof(struct iphdr));
    }
    /*else if (icmp_flag)
    {
        generate_icmp_packet(packet, icmp_type, icmp_code);
    }*/


    // Set to socket(AF_PACKET, SOCK_DGRAM, IPPROTO_RAW) if you want to
    // manually set link-layer headers
    // Must run as root, otherwise socket creation will fail
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s == -1)
    {
        printf("errno: %s\n", strerror(errno));
    }
    c = sendto(s, packet, ip_header->tot_len, 0, (struct sockaddr*) &sock_dest,
            sizeof(sock_dest));
    printf("sendto rv: %d\n", c);
    if (c == -1)
    {
        printf("errno: %s\n", strerror(errno));
    }

    close(s);

    return 0;
}

u_int32_t generate_ip_header(struct iphdr* ip_header, const char* src_addr,
        const char* dst_addr, const char* ip_ttl)
{
    u_int32_t src, dst;
    inet_aton(src_addr, (struct in_addr*) &src);
    inet_aton(dst_addr, (struct in_addr*) &dst);

    ip_header->id = 0;
    ip_header->frag_off = 0;
    ip_header->ttl = strtol(ip_ttl, NULL, 10);
    ip_header->check = 0;
    ip_header->saddr = src;
    ip_header->daddr = dst;

    return src;
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
    void* csum_hdr = malloc(sizeof(struct tcppshdr) + sizeof(struct tcphdr));

    struct tcppshdr tcp_pseudo_header;// = malloc(sizeof(struct tcppshdr));
    struct tcphdr* tcp_hdr = (struct tcphdr*) (packet + sizeof(struct iphdr));
    tcp_hdr->source = strtol(src_port, NULL, 10);
    tcp_hdr->dest = strtol(dst_port, NULL, 10);
    tcp_hdr->seq = strtol(tcp_seq_num, NULL, 10);
    tcp_hdr->ack_seq = strtol(tcp_ack_num, NULL, 10);
    tcp_hdr->doff = 5;
    tcp_hdr->urg = 0;
    tcp_hdr->ack = 0;
    tcp_hdr->psh = 0;
    tcp_hdr->rst = 0;
    tcp_hdr->syn = 0;
    tcp_hdr->fin = 0;
    tcp_hdr->window = strtol(tcp_win_size, NULL, 10);
    tcp_hdr->urg_ptr = 0;

    tcp_pseudo_header.src = (u_int32_t) tcp_hdr->source;
    tcp_pseudo_header.dst = (u_int32_t) tcp_hdr->dest;
    tcp_pseudo_header.proto = IPPROTO_TCP;
    tcp_pseudo_header.len = sizeof(struct tcphdr);

    flag_len = strlen(tcp_flags);
    for (i = 0; i < flag_len; i++)
    {
        switch (toupper(tcp_flags[i]))
        {
            case 'U':
                tcp_hdr->urg = 1;
                break;

            case 'A':
                tcp_hdr->ack = 1;
                break;

            case 'P':
                tcp_hdr->psh = 1;
                break;

            case 'R':
                tcp_hdr->rst = 1;
                break;

            case 'S':
                tcp_hdr->syn = 1;
                break;

            case 'F':
                tcp_hdr->fin = 1;
                break;

            default:
                printf("Invalid TCP flag");
                abort();
        }
    }

    memcpy(csum_hdr, &tcp_pseudo_header, sizeof(tcp_pseudo_header));
    memcpy(csum_hdr + sizeof(struct tcppshdr), tcp_hdr, sizeof(struct tcphdr));
    tcp_hdr->check = checksum((u_int16_t*) csum_hdr,
        sizeof(struct tcphdr) + sizeof(struct tcppshdr));

    //free(tcp_pseudo_header);
    free(csum_hdr);
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
            (*target)[j] = '\0';
            j = 0;
        }
        else
        {
            (*target)[j++] = addr_port[i];
        }
    }
    (*target)[j] = '\0';

    return;
}

// length is in bytes, calculates checksum based on 16 bit words
u_int16_t checksum(u_int16_t* data, int len)
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

    return ~((u_int16_t) sum);
}
