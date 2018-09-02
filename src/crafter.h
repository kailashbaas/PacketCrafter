#ifndef CRAFTER_H
#define CRAFTER_H
#include <getopt.h>
#include <netinet/ip.h>

u_int32_t generate_ip_header(struct iphdr* ip_header, const char* src_addr,
        const char* dst_addr, const char* ip_ttl);
void generate_udp_packet(char* packet, const char* src_port,
        const char* dst_port);
void generate_tcp_packet(char* packet, const char* src_port,
        const char* dst_port, const char* tcp_flags, const char* tcp_seq_num,
        const char* tcp_ack_num, const char* tcp_win_size);
void generate_icmp_packet(const char* packet, const char* icmp_type,
        const char* icmp_code);
void parseAddrPort(const char* addr_port, char* addr, char* port);
u_int16_t checksum(u_int16_t* data, int len);
#endif
