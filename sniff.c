#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>
#include <arpa/inet.h>

#include "net-headers.h"
#include "util.h"

void verbose_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int decode_ethernet(const u_char *packet, int verbose, char *next_proto);
int decode_arp(const u_char *packet, int verbose);
int decode_ip(const u_char *packet, int verbose, char *next_proto);
int decode_icmp(const u_char *packet, int verbose);
int decode_tcp(const u_char *packet, int verbose);
int decode_udp(const u_char *packet, int verbose);

int main(int argc, char *argv[]){
    pcap_t *handle;                     // session handler de pcap
    char *device;                       // nombre de la interfaz de red
    char errbuf[PCAP_ERRBUF_SIZE];      // buffer para guardar mensajes de error

    char filter_exp[] = "tcp";          // filtro para paquetes de red
    struct bpf_program filter_compiled; // filtro compilado
    bpf_u_int32 mask;                   // netmask de la interfaz de red
    bpf_u_int32 net;                    // IP de la interfaz de red

    char *dst;                          // puntero a string generico           

    void (*callback)(u_char *, const struct pcap_pkthdr *, const u_char *);

    /* conseguir automaticamente la interfaz de red */
    device = pcap_lookupdev(errbuf);
    if(device == NULL){
        printf("[ERROR] at pcap_lookupdev: %s\n", errbuf);
        return 1;
    }
    printf("Device is: %s, ", device);

    /* conseguir informacion de la interfaz  */
    if(pcap_lookupnet(device, &net, &mask, errbuf) == -1){
        printf("[ERROR] at pcap_lookupnet: %s\n", errbuf);
        return 1;
    }
    if( (dst = (char *)malloc(INET_ADDRSTRLEN)) == NULL){ // INET_ADDRSTRLEN = 16 bytes == len(xxx.xxx.xxx.xxx\0)
        printf("[ERROR] at malloc\n");
        return 1;
    }
    inet_ntop(AF_INET, &net, dst, INET_ADDRSTRLEN);
    printf("net: %s, ", dst);
    inet_ntop(AF_INET, &mask, dst, INET_ADDRSTRLEN);
    printf("mask: %s\n", dst);
    free(dst);

    /* crear la sesion  */
    handle = pcap_open_live(device, 4096, 1, 0, errbuf); // 1 = modo promiscuo
    if(handle == NULL){
        printf("[ERROR] at pcap_open_live: %s\n", errbuf);
        return 1;
    }

    /* compilar el filtro de paquetes de red */
    if(pcap_compile(handle, &filter_compiled, filter_exp, 0, net) == -1){
        printf("[ERROR] at pcap_compile: %s\n", errbuf);
        return 1;
    }

    /* aplicar el filtro */
    if(pcap_setfilter(handle, &filter_compiled) == -1){
        printf("[ERROR] at pcap_setfilter: %s\n", errbuf);
        return 1;
    }

    /* capturar paquetes  */
    callback = &verbose_packet;
    pcap_loop(handle, 5, callback, NULL);

    pcap_close(handle);
    return 0;
}

void verbose_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    char next_protocol[10];
    int ethernet_hdr_size, ip_hdr_size, tcp_hdr_size, total_hdr_size;
    u_char *start_data;

    printf("======= %d bytes packet =======\n", header->len);

    ethernet_hdr_size = decode_ethernet(packet, 1, next_protocol);
    total_hdr_size = ethernet_hdr_size;

    if(strcmp(next_protocol, ETHERNET_NAME_IPV4) == 0){
        // inicio IPv4 sobre Ethernet
        ip_hdr_size = decode_ip(packet+ethernet_hdr_size, 1, next_protocol);
        total_hdr_size += ip_hdr_size;

        if(strcmp(next_protocol, IP_PROTNAME_TCP) == 0){
            // inicio TCP sobre IP
            tcp_hdr_size = decode_tcp(packet+ethernet_hdr_size+ip_hdr_size, 1);
            total_hdr_size += tcp_hdr_size;

            // fin TCP sobre IP
        }else if(strcmp(next_protocol, IP_PROTNAME_UDP) == 0){
            // inicio UDP sobre IP
            decode_udp(packet+ethernet_hdr_size+ip_hdr_size, 1);
            total_hdr_size += sizeof(struct udp);

            // fin UDP sobre IP
        }else if(strcmp(next_protocol, IP_PROTNAME_ICMP) == 0){
            // inicio ICMP sobre IP
            decode_icmp(packet+ethernet_hdr_size+ip_hdr_size, 1);
            total_hdr_size += sizeof(struct icmp); 

            // fin ICMP sobre IP
        }
        // fin IPV4 sobre Ethernet
    }else if(strcmp(next_protocol, ETHERNET_NAME_ARP) == 0){
        // inicio ARP sobre Ethernet
        decode_arp(packet+ethernet_hdr_size, 1);
        total_hdr_size += sizeof(struct arp);

        // fin ARP sobre Ethernet
    }

    start_data = (u_char *)(packet + total_hdr_size);

    if((header->len - total_hdr_size) > 0){
        printf("Data:\n");
        hexdump(start_data, header->len - total_hdr_size, total_hdr_size);
    }else{
        printf("No Data\n");
    }
}

int decode_ethernet(const u_char *packet, int verbose, char *next_proto){
    struct ethernet *ethernet_header;
    char str[ETHERNET_ADDR_STRLEN];

    ethernet_header = (struct ethernet *)packet;

    strcpy(next_proto, ETHERNET_GET_TYPE_NAME(ethernet_header->type));

    if(!verbose){
        return ETHERNET_HEADER_SIZE;
    }

    printf("---Data Link Layer [Ethernet]---\n");

    ETHERNET_ADDR_TO_STR(ethernet_header->dst_addr, str);
    printf("dst addr %s, ", str);
    ETHERNET_ADDR_TO_STR(ethernet_header->src_addr, str);
    printf("src addr %s\n", str);

    printf("Type: 0x%04x (%s)\n", ntohs(ethernet_header->type), next_proto);
    
    return ETHERNET_HEADER_SIZE;
}

int decode_ip(const u_char *packet, int verbose, char *next_proto){
    struct ip *ip_header;
    int header_length;
    char str[INET_ADDRSTRLEN];
    char flag_buffer[30];

    ip_header = (struct ip *)packet;

    strcpy(next_proto, IP_GET_PROTOCOL_NAME(ip_header->protocol));

    header_length = 4 * IP_GET_IHL(ip_header->version_and_ihl);

    if(!verbose){
        return header_length;
    }

    printf("---Network Layer [IP]---\n");

    inet_ntop(AF_INET, (struct in_addr *)&(ip_header->src_addr), str, INET_ADDRSTRLEN);
    printf("src addr %s, ", str);
    inet_ntop(AF_INET, (struct in_addr *)&(ip_header->dst_addr), str, INET_ADDRSTRLEN);
    printf("dst addr %s\n", str);

    printf("version: %d, ihl: %d\n", IP_GET_VERSION(ip_header->version_and_ihl), IP_GET_IHL(ip_header->version_and_ihl));

    printf("type of service: 0x%02x\n", ip_header->type_of_service);

    printf("total length %d bytes\n", ntohs(ip_header->total_length));

    printf("identification: 0x%04x\n", ntohs(ip_header->identification));

    IP_GET_SET_FLAGS(ip_header->flags_and_fragment_offset, flag_buffer);
    printf("set flags: %s\n", flag_buffer);

    printf("fragment offset %d\n", IP_GET_FRAGMENT_OFFSET(ip_header->flags_and_fragment_offset));

    printf("time to live: %d\n", ip_header->time_to_live);

    printf("protocol: 0x%02x (%s)\n", ip_header->protocol, next_proto);

    printf("header checksum: 0x%04x\n", ntohs(ip_header->header_checksum));

    return header_length;
}

int decode_tcp(const u_char *packet, int verbose){
    struct tcp *tcp_header;
    int header_length;
    char flag_buffer[40]; //ajustar tamaño

    tcp_header = (struct tcp *)packet;

    header_length = 4 * TCP_GET_DATA_OFFSET(tcp_header->data_offset_and_flags);

    if(!verbose){
        return header_length;
    }

    printf("---Transport Layer [TCP]---\n");

    printf("src port: %u, dst port: %u\n", ntohs(tcp_header->src_port), ntohs(tcp_header->dst_port));

    printf("seq number: %u, ack number: %u\n", ntohl(tcp_header->seq_number), ntohl(tcp_header->ack_number));

    printf("data offset: %u\n", TCP_GET_DATA_OFFSET(tcp_header->data_offset_and_flags));

    TCP_GET_SET_FLAGS(tcp_header->data_offset_and_flags, flag_buffer);
    printf("set flags: %s\n", flag_buffer);

    printf("window: %u\n", ntohs(tcp_header->window));

    printf("checksum: 0x%04x\n", ntohs(tcp_header->checksum));

    printf("urgent pointer: %u\n", ntohs(tcp_header->urgent_pointer));

    return header_length;
}

int decode_udp(const u_char *packet, int verbose){
    struct udp *udp_header;
    int udp_packet_length;

    udp_header = (struct udp *)packet;

    udp_packet_length = ntohs(udp_header->length);
    
    if(!verbose){
        return udp_packet_length;
    }

    printf("---Transport Layer [UDP]---\n");

    printf("src port: %u, dst port: %u\n", ntohs(udp_header->src_port), ntohs(udp_header->dst_port));

    printf("packet length %d\n", udp_packet_length);

    printf("checksum: 0x%04x\n", ntohs(udp_header->checksum));

    return udp_packet_length;
}

int decode_arp(const u_char *packet, int verbose){
    // TODO: pensar el valor a devolver
    struct arp *arp_header;
    char stre[ETHERNET_ADDR_STRLEN], stri[INET_ADDRSTRLEN];

    arp_header = (struct arp *)packet;

    if(!verbose){
        return 0;
    }

    printf("---ARP---\n");

    printf("hardware type: %u\n", ntohs(arp_header->hardware_type));

    printf("protocol type: 0x%04x\n", ntohs(arp_header->protocol_type));

    printf("hardware addr len: %u\n", arp_header->hardware_addr_length);

    printf("protocol addr len: %u\n", arp_header->protocol_addr_length);

    printf("opcode: %u\n", ntohs(arp_header->opcode)); 

    ETHERNET_ADDR_TO_STR(arp_header->sender_hardware_addr, stre);
    printf("sender MAC addr: %s\n", stre);

    inet_ntop(AF_INET, (struct in_addr *)&(arp_header->sender_protocol_addr), stri, INET_ADDRSTRLEN);
    printf("sender IP addr: %s\n", stri);

    ETHERNET_ADDR_TO_STR(arp_header->target_hardware_addr, stre);
    printf("target MAC addr: %s\n", stre);

    inet_ntop(AF_INET, (struct in_addr *)&(arp_header->target_protocol_addr), stri, INET_ADDRSTRLEN);
    printf("target IP addr: %s\n", stri);

    return 0;
}

int decode_icmp(const u_char *packet, int verbose){
    //TODO: pensar el valor a devolver
    struct icmp *icmp_header;

    icmp_header = (struct icmp *)packet;

    if(!verbose){
        return 0;
    }

    printf("---ICMP---\n");

    printf("type: %u\n", icmp_header->type); 

    printf("code: %u\n", icmp_header->code);

    printf("checksum: 0x%04x\n", ntohs(icmp_header->checksum));

    printf("rest of header: 0x%08x\n", ntohl(icmp_header->rest_of_header));

    return 0;
}
