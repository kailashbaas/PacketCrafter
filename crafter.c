#include "crafter.h"
#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
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

    int c, udp_flag = 0, tcp_flag = 0, icmp_flag = 0;

    //generate_long_options(param_config_file, &udp_flag, &tcp_flag, &icmp_flag, long_options);
    static struct option long_options[] = //generate_long_options(param_config_file,
    //        &udp_flag, &tcp_flag, &icmp_flag);
    {
        {"udp", no_argument, &udp_flag, 1},
        {"tcp", no_argument, &tcp_flag, 1},
        {"icmp", no_argument, &icmp_flag, 1},
        {"src", required_argument, 0, "s"},
        {"dest", required_argument, 0, "d"},
        {"tcpflag", required_argument, 0, "l"},
        {"seqnum", required_argument, 0, "e"},
        {"acknum", required_argument, 0, "k"},
        {"window", required_argument, 0, "w"},
        {"ipttl", required_argument, 0, "t"},
        {"icmptype", required_argument, 0, "y"},
        {"icmpcode", required_argument, 0, "c"},
        {0, 0, 0, 0}
    };

    int option_index = 0;

    // TODO: set these to default values from file
    // Add 1 to the lengths for the null char
    char src_address[IP_ADDRESS_LEN + 1], dest_address[IP_ADDRESS_LEN + 1], tcp_flags[NUM_TCP_FLAGS + 1];
    char tcp_seq_num[TCP_SEQ_ACK_LEN + 1], tcp_ack_num[TCP_SEQ_ACK_LEN + 1], tcp_win_size[TCP_WIN_SIZE_LEN + 1];
    char ip_ttl[IP_TTL_LEN + 1], icmp_type[ICMP_TYPE_LEN + 1], icmp_code[ICMP_CODE_LEN + 1];

    while (1)
    {
        c = getopt_long(argc, argv, "utis:d:l:e:k:w:t:y:c:", long_options, &option_index);
        switch (c)
        {
            case 0:
                break;

            case "s":
                strcpy(src_address, optarg);
                break;

            case "d":
                strcpy(dest_address, optarg);
                break;

            case "l":
                strcpy(tcp_flags, optarg);
                break;

            case "e":
                strcpy(tcp_seq_num, optarg);
                break;

            case "k":
                strcpy(tcp_ack_num, optarg);
                break;

            case "w":
                strcpy(tcp_win_size, optarg);
                break;

            case "t":
                strcpy(ip_ttl, optarg);
                break;

            case "y":
                strcpy(icmp_type, optarg);
                break;

            case "c":
                strcpy(icmp_code, optarg);
                break;

            default:
                abort();
        }
    }

    char packet[4096];
    memset(packet, 0, 4096);

    if (udp_flag)
    {
        generate_udp_packet(packet, src_address, dest_address, ip_ttl);
    }
    else if (tcp_flag)
    {
        generate_tcp_packet(packet, src_address, dest_address, tcp_flags,
                tcp_seq_num, tcp_ack_num, tcp_win_size, ip_ttl);
    }
    else if (icmp_flag)
    {
        generate_icmp_packet(packet, src_address, dest_address, icmp_type, icmp_code);
    }

    return 0;
}

void generate_udp_packet(char* packet, char* src_address, char* dest_address,
        char* ip_ttl)
{
    char* src_ip, *src_port, *dst_ip, *dst_port;
    parseAddrPort(src_address, src_ip, src_port);
    parseAddrPort(dst_address, dst_ip, dst_port);
    char** src, **dst;
    int i, j = 0;
    int src_len = strlen(src_address), dst_len = strlen(dest_address);

    for (i = 0; i < src_len; i++)
    {
        if (src_address[i] == ":")
        {
            src = src_port;
            j = 0;
        }
        else
        {
            src->[j++] = src_address[i];
        }
    }

    struct iphdr* ip_header = (struct iphdr*) packet;
    struct udphdr* udp_header = (struct udphdr*) (packet + (sizeof(struct iphdr)));

    ip_header->tot_len = sizeof(struct udphdr) + sizeof(struct iphdr);
    ip_header->id = 0;
    ip_header->frag_off = 0;
    ip_header->ttl = strtol(ip_ttl, NULL, 10);
    ip_header->protocol = 17;
}

void parseAddrPort(char* addr_port, char* addr, char* port);
/*void generate_long_options(const char* filename, int* udp_flag,
        int* tcp_flag, int* icmp_flag, struct options* long_options)
{
    int c, argtype, i = 0, param_num = 0, *flag, num_val;
    char char_value;
    enum OptionField field = NAME;
    char* name, *has_arg, *val, *string;
    //static struct options long_options[num_params];
    FILE* fp = fopen(filename, "r");

    while ((c = fgetc(fp)) != EOF)
    {
        char_value = (char) c;
        if (char_value == ':')
        {
            string[i] = '\0';
            i = 0;
            if (field == NAME)
            {
                strcpy(name, string);
                field = HAS_ARG;
            }
            else
            {
                strcpy(has_arg, string);
                field = VAL;
            }
        }
        else if (char_value == '\n')
        {
            argtype = strcmp(has_arg, "r");
            string[i] = '\0';
            strcpy(val, string);
            if (strcmp(name, "tcp"))
            {
                flag = tcp_flag;
            }
            else if (strcmp(name, "udp"))
            {
                flag = udp_flag;
            }
            else if (strcmp(name, "icmp"))
            {
                flag = icmp_flag;
            }
            else
            {
                flag = NULL;
            }
            long_options[param_num++] = { .name = name, .has_arg = argtype, .flag = flag, .val = val[0] };
        }
        else
        {
            string[i++] = c;
        }
    }
}*/