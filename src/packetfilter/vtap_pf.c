/* This program reads in data from either an interface or a pcap file with
 * data from Azure V-TAP and prints out the "inner" packet while discarding
 * the outer packet
 */
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>  
#include <net/ethernet.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN  6
#endif
#define ETH_HDR_SIZE    14
#define FILTER_EXP_LEN  256
#define DEFAULT_FILTER_EXP "udp and port 4789"
#define IPv4_ADDR_LEN   16
#define MAX_BUF_SIZE    256

//Identify packet types
#define ICMP_PACKET     0x01
#define IP_IN_IP_PACKET 0x04
#define TCP_PACKET      0x06
#define EGP_PACKET      0x08
#define IGP_PACKET      0x09
#define UDP_PACKET      0x17


struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

struct sniff_udp {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t cksum;
};

struct sniff_vxlan {
    uint64_t flags:8;
    uint64_t reserved:24;
    uint64_t vni:24;
    uint64_t reserved2:8;
};

struct tcpInfo {
    char ip[IPv4_ADDR_LEN];
    u_short port;
    struct servent *service;
};

#define UDP_SIZE sizeof(struct sniff_udp)
#define VXLAN_SIZE sizeof(struct sniff_vxlan)


void handle_tcp(const u_char *packet)
{
    struct sniff_ip *ip = (struct sniff_ip *)packet;
    struct sniff_tcp *tcp;
    u_int ip_size;
    u_int tcp_size;
    struct tcpInfo src, dst;
    char buf[MAX_BUF_SIZE];
    char src_buf[MAX_BUF_SIZE/8], dst_buf[MAX_BUF_SIZE/8];

    if(NULL == ip) {
        printf("ERROR: received NULL packet\n");
        return;
    }
    ip_size = IP_HL(ip)*4;
    tcp = (struct sniff_tcp *)((u_char *)ip + ip_size);
    tcp_size = TH_OFF(tcp)*4;
    if(20 > tcp_size) {
        printf("TCP packet size < 20 bytes [%d]\n", tcp_size);
        return;
    }
    memset(buf, 0, MAX_BUF_SIZE);
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    memset(&src_buf, 0, sizeof(src_buf));
    memset(&dst_buf, 0, sizeof(dst_buf));
    strncpy(src.ip, inet_ntoa(ip->ip_src), IPv4_ADDR_LEN);
    src.port = ntohs(tcp->th_sport);
    src.service = getservbyport(tcp->th_sport, "tcp");
    if(src.service == NULL) {
        snprintf(src_buf, MAX_BUF_SIZE/8, "%s:%d", src.ip, src.port);
    } else {
        snprintf(src_buf, MAX_BUF_SIZE/8, "%s:%s", src.ip, src.service->s_name);
    }
    strncpy(dst.ip, inet_ntoa(ip->ip_dst), IPv4_ADDR_LEN);
    dst.port = ntohs(tcp->th_dport);
    dst.service = getservbyport(tcp->th_dport, "tcp");
    if(dst.service == NULL) {
        snprintf(dst_buf, MAX_BUF_SIZE/8, "%s:%d", dst.ip, dst.port);
    } else {
        snprintf(dst_buf, MAX_BUF_SIZE/8, "%s:%s", dst.ip, dst.service->s_name);
    }
    snprintf(buf, MAX_BUF_SIZE-16, "TCP,%s,%s", src_buf, dst_buf);
    if(tcp->th_flags & TH_SYN) {
        strncat(buf, ",SYN", 4);
    } 
    if(tcp->th_flags & TH_ACK) {
        strncat(buf, ",ACK", 4);
    } 
    if(tcp->th_flags & TH_RST) {
        strncat(buf, ",RST", 4);
    }
    printf("%s\n", buf);
}

void process_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet)
{
    struct sniff_ethernet *eth_outer, *eth_inner;
    struct sniff_ip *ip_outer, *ip_inner;
    struct sniff_udp *udp;
    struct sniff_vxlan *vxlan;
    u_int eth_size = ETH_HDR_SIZE;
    u_int ip_size;

    eth_outer = (struct sniff_ethernet *)packet;
    if(0x81 == ntohs(eth_outer->ether_type)) {
        eth_size += 4; //Skip VLAN header
    }
    ip_outer = (struct sniff_ip *)(packet + eth_size);
    ip_size = IP_HL(ip_outer)*4;
    if(20 > ip_size) {
        printf("ERROR: IP header length < 20 bytes[%d]\n", ip_size);
        return;
    }
    //TODO: Process UDP and VXLAN, ignoring for now
    udp = (struct sniff_udp *)((u_char *)ip_outer + ip_size);
    vxlan = (struct sniff_vxlan *)((u_char *)udp + UDP_SIZE);

    eth_size = ETH_HDR_SIZE;
    eth_inner = (struct sniff_ethernet *)((u_char *)vxlan + VXLAN_SIZE);
    if(0x81 == ntohs(eth_inner->ether_type)) {
        eth_size += 4; //Skip VLAN header
    }
    ip_inner = (struct sniff_ip *)((u_char *)eth_inner + eth_size);
    ip_size = IP_HL(ip_inner)*4;
    if(20 > ip_size) {
        printf("ERROR: Inner IP header length < 20 bytes[%d]\n", ip_size);
        return;
    }
    switch((int)ip_inner->ip_p) {
        case ICMP_PACKET:
            printf("ICMP packet\n");
            //handle_icmp((u_char *)ip);
            break;
        case IP_IN_IP_PACKET:
            printf("IP in IP packet\n");
            //handle_ip_in_ip((u_char *)ip_inner);
            break;
        case TCP_PACKET:
            //printf("TCP packet\n");
            handle_tcp((u_char *)ip_inner);
            break;
        case EGP_PACKET:
            printf("EGP packet\n");
            //handle_EGP((u_char *)ip_inner);
            break;
        case IGP_PACKET:
            printf("IGP packet\n");
            //handle_IGP((u_char *)ip_inner);
            break;
        case UDP_PACKET:
            printf("UDP packet\n");
            //handle_udp((u_char *) + ip_size);
            break;
    }
}

int main(int argc, char **argv)
{
    int c;
    pcap_t *h;
    struct bpf_program fp;
    char filter_exp[FILTER_EXP_LEN];
    char *dev = NULL;
    char pcap_err[PCAP_ERRBUF_SIZE];
    char *filename = NULL;
    int rv;

    memset(filter_exp, 0, FILTER_EXP_LEN);
    while((c = getopt(argc, argv, "i:p:f:")) != -1) {
        switch (c) {
            case 'i':
                dev = strndup(optarg, strlen(optarg));
                break;
            case 'p':
                filename = strndup(optarg, strlen(optarg));
                break;
            case 'f':
                strncpy(filter_exp, optarg, FILTER_EXP_LEN);
                break;
            default:
                printf("unknown option %c\n", c);
                printf("usage: %s [-i <eth_dev> | -p <pcap_file>] -f <filter_exp>\n", argv[0]);
                printf("where:\n<eth_dev>\tEthernet device to monitor\n");
                printf("<pcap_file>:\tPath to pcap file to read\n");
                printf("<filter_exp>:\tOptional Filter expression similar to tcpdump\n");
                printf("\t\tdefault filter exp --> '%s'\n", DEFAULT_FILTER_EXP);
        }
    }

    if(0 == strlen(filter_exp)) {
        strncpy(filter_exp, DEFAULT_FILTER_EXP, strlen(DEFAULT_FILTER_EXP));
    }

    if(NULL == dev && NULL == filename) {
        printf("no device specified, using eth0\n");
        dev = strndup("eth0", 4);
    }

    if(NULL != dev) {
        h = pcap_open_live(dev, BUFSIZ, 1, 1000, pcap_err);
        if(NULL == h) {
            printf("pcap_open_live(%s) returned %s\n", dev, pcap_err);
            return(-1);
        }
    } else {
        h = pcap_open_offline_with_tstamp_precision(filename, PCAP_TSTAMP_PRECISION_MICRO, pcap_err);
        if(NULL == h) {
            printf("pcap_open_offline(%s) returned %s\n", filename, pcap_err);
            return(-1);
        }
    }

    rv = pcap_compile(h, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN);
    if(-1 == rv) {
        printf("ERROR:pcap_compile() returned [%s]\n", pcap_geterr(h));
        pcap_close(h);
        return(-1);
    }

    rv = pcap_setfilter(h, &fp);
    if(-1 == rv) {
        printf("ERROR:pcap_setfilter() returned [%s]\n", pcap_geterr(h));
        pcap_close(h);
        return(-1);
    }
    pcap_freecode(&fp);
    while(1) {
        rv = pcap_dispatch(h, 0, process_packet, (u_char *)h);
        if(-1 == rv) {
            printf("pcap_dispatch() returned -1\n");
            pcap_close(h);
            return(-1);
        } else if(-2 == rv) {
            printf("Done reading pcap data\n");
            pcap_close(h);
            return(-1);
        } else if(0 == rv && NULL != filename) {
            printf("Done reading pcap file\n");
            pcap_close(h);
            return(0);
        }
    }
    return(0);
}