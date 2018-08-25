#ifndef CRAFTER_H
#define CRAFTER_H
#include <getopt.h>

//void generate_long_options(const char* filename, int* udp_flag, int* tcp_flag, int* icmp_flag, struct options* long_options);
void generate_udp_packet(char* packet, char* src_address, char* dest_address,
        char* ip_ttl);
void generate_tcp_packet(char* packet, char* src_address, char* dest_address,
        char* tcp_flags, char* tcp_seq_num, char* tcp_ack_num,
        char* tcp_win_size, char* ip_ttl);
void generate_icmp_packet(char* packet, char* src_address, char* dest_address,
        char* icmp_type, char* icmp_code);
void parseAddrPort(char* addr_port, char* addr, char* port);
#endif
