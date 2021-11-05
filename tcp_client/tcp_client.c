#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <openssl/sha.h>

#define SRC_PORT 12345

// global tcp sequence number, set to our hashed secret
static unsigned int sequence_number = 0;

// ip pseudo header for tcp csum calc
struct tcp_pseudo_header { //for tcp checksum calculation
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned char reserved; //zero byte
    unsigned char proto;
    unsigned short len;
};

// ip pseudo header for tcp csum calc over ipv6
struct tcp_pseudo_header6 { //for tcp checksum calculation
    struct in6_addr saddr;
    struct in6_addr daddr;
    unsigned int tcp_len;
    unsigned char reserved[3]; // zero bytes
    unsigned char next_header;
};

// some print functions for ip, tcp, hex

/**
 * Print a ip header
 * @param ip
 */
void print_ipv4(struct iphdr *ip){
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    struct sockaddr_in src_, dst_;
    src_.sin_addr.s_addr = ip->saddr;
    dst_.sin_addr.s_addr = ip->daddr;
    inet_ntop(AF_INET, &(src_.sin_addr), src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(dst_.sin_addr), dst, INET_ADDRSTRLEN);

    printf("IPv4 Header:\n\n"
           "Version:\t\t\t4\n"
           "IHL:\t\t\t\t%u (x4)\n"
           "TOS:\t\t\t\t%u\n"
           "Total Length:\t\t%u \n"
           "Identification:\t\t%u \n"
           "Fragment offset:\t%u\n"
           "TTL:\t\t\t\t%u\n"
           "Protocol:\t\t\t%X\n"
           "Checksum:\t\t\t%u\n"
           "Source Address:\t\t%s\n"
           "Dest Address:\t\t%s\n"
           "---------------------------------------------------\n",
           ip->ihl, ip->tos, ntohs(ip->tot_len), ntohs(ip->id), ntohs(ip->frag_off), ip->ttl, ip->protocol, ip->check, src, dst);
}

/**
 * Print a tcp header
 * @param tcp
 */
void print_tcp(struct tcphdr *tcp){
    printf("TCP Header:\n\n"
           "Src Port:\t\t\t%u\n"
           "Dest Port:\t\t\t%u\n"
           "Seq Nr:\t\t\t\t0x%.8x\n"
           "Ack Number:\t\t\t%u\n"
           "Offset:\t\t\t\t%u\n"
           "URG Flag:\t\t\t%u\n"
           "ACK Flag:\t\t\t%u\n"
           "PSH Flag:\t\t\t%u\n"
           "RST Flag:\t\t\t%u\n"
           "SYN Flag:\t\t\t%u\n"
           "FIN Flag:\t\t\t%u\n"
           "Window:\t\t\t\t%u\n"
           "Checksum:\t\t\t%u\n"
           "Urgent Pointer:\t\t%u\n"
           "---------------------------------------------------\n",
           ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq), tcp->doff, tcp->urg, tcp->ack,
           tcp->psh, tcp->rst, tcp->syn, tcp->fin, ntohs(tcp->window), tcp->check, tcp->urg_ptr);
}

/**
 * print hexdump
 * @param header
 * @param type identifier
 * @param len
 */
void print_hex(void *header, char type[], int len){
    char *datagram = (char*) header;   //set datagram pointer to header
    printf("%s\n\n0x0000\t", type);
    for (int i = 0; i < len; i++){
        if (i != 0 && i % 16 == 0){
            printf("\n0x%04x\t", i);
        }
        printf("%02x ", datagram[i] & 0xff);
        if((i+1) % 8 == 0 && (i+1) % 16 != 0)printf(" ");
    }
    printf("\n---------------------------------------------------\n");
}

/**
 * Get my own ipv4 from interface
 * @param iface e.g. lo0, en0
 * @param dst
 * @return 0 on success, -1 else
 */
int get_my_ip4(const char *iface, struct in_addr *dst) {

    struct ifaddrs *addr1, *addr2;

    if (0 > getifaddrs(&addr1)){
        exit(EXIT_FAILURE);
    }
    addr2 = addr1;

    while(addr2){
        if (addr2->ifa_addr && addr2->ifa_addr->sa_family == AF_INET){
            // we have a ipv4 interface
            if (!strcmp(iface, addr2->ifa_name)) {
                // found correct interface
                struct sockaddr_in *addr = (struct sockaddr_in *) addr2->ifa_addr;
                memcpy(dst, &addr->sin_addr, sizeof(struct in_addr));
                freeifaddrs(addr1);
                return 0;
            }
        }
        addr2 = addr2->ifa_next;
    }

    return -1;
}

/**
 * Get my own ipv6 from interface
 * @param iface e.g. lo0, en0
 * @param dst
 * @return 0 on success, -1 else
 */
int get_my_ip6(const char *iface, struct in6_addr *dst) {

    struct ifaddrs *addr1, *addr2;

    if (0 > getifaddrs(&addr1)){
        exit(EXIT_FAILURE);
    }
    addr2 = addr1;

    while(addr2){
        if (addr2->ifa_addr && addr2->ifa_addr->sa_family == AF_INET6){
            // we have a ipv6 interface
            if (!strcmp(iface, addr2->ifa_name)) {
                // found correct interface
                struct sockaddr_in6 *addr = (struct sockaddr_in6 *) addr2->ifa_addr;
                memcpy(dst, &addr->sin6_addr, sizeof(struct in6_addr));
                freeifaddrs(addr1);
                return 0;

            }

        }

        addr2 = addr2->ifa_next;
    }

    return -1;
}

/**
 * Include the iphdr into raw socket packet
 * @param fd
 * @return
 */
int include_iphdr(int fd, unsigned char ip_version){
    int one = 1, ret;
    const int *val = &one;
    if (ip_version == 4) {
        ret = setsockopt(fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));
    } else {
        ret = setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL, val, sizeof(one));
    }

    return ret;
}

/**
 * Calculate network stack csums
 * @param ptr
 * @param nbytes
 * @return csum
 */
unsigned short csum(unsigned short *ptr, int nbytes){
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1){
        sum+=*ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1){
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return (unsigned short) answer;
}

/**
 * Generate a tcp over ipv4 packet
 * @param packet
 * @param len
 * @param saddr
 * @param daddr
 * @param sport
 * @param dport
 * @param seq_nr
 * @param ack_seq_nr
 * @param fin
 * @param syn
 * @param rst
 * @param ack
 * @param window
 * @return
 */
void generate_tcp_over_ipv4_package(unsigned char *packet, unsigned short len, unsigned int saddr, unsigned int daddr,
                                    unsigned short sport, unsigned short dport, unsigned int seq_nr, unsigned int ack_seq_nr,
                                    unsigned char fin, unsigned char syn, unsigned char rst, unsigned char ack, unsigned short window) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct tcp_pseudo_header ph;
    unsigned char *pseudo_package;

    iph = (struct iphdr *) packet;
    tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));

    // fill the ip package
    iph->version = 0x4; //ipv4
    iph->ihl = 0x5; // no options, minimum ip len = 5 * 4 = 20 byte
    iph->tos = 0x0; // normal delay
    len += sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->tot_len = htons(len); //len = iphdr + next_headers + payload (in bytes)
    iph->id = htons(0x0); // identification number
    iph->frag_off = 0x40; // DF
    iph->ttl = 0x40;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0x0;
    iph->saddr = saddr;
    iph->daddr = daddr;

    // calculate ip csum
    iph->check = csum((unsigned short *) packet, sizeof(struct iphdr));

    // fill tcphdr
    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = htonl(seq_nr);
    tcph->ack_seq = htonl(ack_seq_nr); // next expected seq_nr
    tcph->doff = 5; // data offset = tcp header len without payload. We do not want tcp options
    tcph->fin = fin; // finish flag, no more packets from sender
    tcph->syn = syn; // syn flag
    tcph->rst = rst; // abort connection
    tcph->psh = 0; // push flag not used in our case
    tcph->ack = ack; // ack flag
    tcph->urg = 0; // urgent flag never used in our case
    tcph->window = htons(window); // maximum receive window
    tcph->check = 0x0;
    tcph->urg_ptr = 0x0; // urgent ptr not used in our case


    // generate pseudo header for tcp csum
    ph.proto = IPPROTO_TCP;
    ph.len = htons(sizeof(struct tcphdr));
    ph.reserved = 0;
    ph.src_addr = saddr;
    ph.dst_addr = daddr;

    pseudo_package = (unsigned char *) malloc(sizeof(struct tcp_pseudo_header) + sizeof(struct tcphdr));

    memset(pseudo_package, 0, sizeof(pseudo_package));
    memcpy(pseudo_package, &ph, sizeof(struct tcp_pseudo_header));
    memcpy(pseudo_package + sizeof(struct tcp_pseudo_header), tcph, sizeof(struct tcphdr));

    // calculate tcp csum
    tcph->check = csum((unsigned short *) pseudo_package, sizeof(struct tcp_pseudo_header) + sizeof(struct tcphdr));

    free(pseudo_package);
}

/**
 * Generate tcp over ipv6 packet
 * @param packet
 * @param len
 * @param saddr
 * @param daddr
 * @param sport
 * @param dport
 * @param seq_nr
 * @param ack_seq_nr
 * @param fin
 * @param syn
 * @param rst
 * @param ack
 * @param window
 */
void generate_tcp_over_ipv6_package(unsigned char *packet, unsigned int len, struct in6_addr *saddr, struct in6_addr *daddr,
                                    unsigned short sport, unsigned short dport, unsigned int seq_nr, unsigned int ack_seq_nr,
                                    unsigned char fin, unsigned char syn, unsigned char rst, unsigned char ack, unsigned short window) {
    struct ip6_hdr *iph;
    struct tcphdr *tcph;
    struct tcp_pseudo_header6 ph;
    unsigned char *pseudo_package;

    iph = (struct ip6_hdr *) packet;
    tcph = (struct tcphdr *) (packet + sizeof(struct ip6_hdr));

    // fill the ip package
    iph->ip6_flow = htonl((6 << 28) + 1); // 4 bit version, 8 bit traffic class, 20 bit flow label
    iph->ip6_plen = htons(sizeof(struct tcphdr) + len); // payload length
    iph->ip6_nxt = IPPROTO_TCP;
    iph->ip6_hops = 0x40; // hop limit
    memcpy(&iph->ip6_src, saddr, sizeof(struct in6_addr));
    memcpy(&iph->ip6_dst, daddr, sizeof(struct in6_addr));

    // fill tcphdr
    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = htonl(seq_nr);
    tcph->ack_seq = htonl(ack_seq_nr); // next expected seq_nr
    tcph->doff = 5; // data offset = tcp header len without payload. We do not want tcp options
    tcph->fin = fin; // finish flag, no more packets from sender
    tcph->syn = syn; // syn flag
    tcph->rst = rst; // abort connection
    tcph->psh = 0; // push flag not used in our case
    tcph->ack = ack; // ack flag
    tcph->urg = 0; // urgent flag never used in our case
    tcph->window = htons(window); // maximum receive window
    tcph->check = 0x0;
    tcph->urg_ptr = 0x0; // urgent ptr not used in our case


    // generate pseudo header ip6 for tcp csum
    ph.next_header = IPPROTO_TCP;
    ph.tcp_len = htonl(sizeof(struct tcphdr));
    memset(ph.reserved, 0, 3);
    memcpy(&ph.saddr, saddr, sizeof(struct in6_addr));
    memcpy(&ph.daddr, daddr, sizeof(struct in6_addr));

    pseudo_package = (unsigned char *) malloc(sizeof(struct tcp_pseudo_header6) + sizeof(struct tcphdr));

    memset(pseudo_package, 0, sizeof(pseudo_package));
    memcpy(pseudo_package, &ph, sizeof(struct tcp_pseudo_header6));
    memcpy(pseudo_package + sizeof(struct tcp_pseudo_header6), tcph, sizeof(struct tcphdr));

    // calculate tcp csum
    tcph->check = csum((unsigned short *) pseudo_package, sizeof(struct tcp_pseudo_header6) + sizeof(struct tcphdr));

    free(pseudo_package);
}

/**
 * TCP handshake
 * @param fd
 * @param dst
 * @param saddr
 * @return 0 on success, -1 else
 */
int raw_connect(int fd, struct sockaddr_in *dst, struct in_addr *saddr) {

    unsigned char packet[2048 + 40] = {0}; // 40 = sizeof(iphdr) + sizeof(tcphdr)
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int remote_seq;

    // send tcp syn with ISN
    generate_tcp_over_ipv4_package(packet, 0, saddr->s_addr, dst->sin_addr.s_addr, SRC_PORT, ntohs(dst->sin_port), sequence_number, 0, 0, 1, 0, 0,
                                   sizeof(packet) - sizeof(struct iphdr) - sizeof(struct tcphdr));

    if (0 > sendto(fd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) dst, sizeof(struct sockaddr_in))) {
        printf("[-] Cannot send packet\n");
        return -1;
    }
    memset(packet, 0, sizeof(packet));

    // wait for tcp syn ack where ack = ISN + 1, seq_nr = y
    while (1) {
        // recv a package on the raw socket
        if (0 > recv(fd, packet, sizeof(packet) - sizeof(struct iphdr) - sizeof(struct tcphdr), 0)) {
            // possibly a timeout occurs
            printf("[-] Cannot recv packet\n");
            return -1;
        }

        // we have received a package, check if it is SYN ACK
        iph = (struct iphdr *) packet;
        if (iph->version != 0x4 || iph->protocol != IPPROTO_TCP) {
            printf("[-] Not a TCP IPv4 packet\n");
            continue;
        }

        tcph = (struct tcphdr *) (packet + iph->ihl * 4);

        // we have to skip packets that are not part of our communication
        if (ntohs(tcph->dest) != SRC_PORT || ntohs(tcph->source) != ntohs(dst->sin_port))
            continue;

        print_tcp(tcph);
        if (tcph->syn != 1 || tcph->ack != 1 || ntohl(tcph->ack_seq) != sequence_number + 1) {
            printf("[-] Not a TCP SYN ACK packet with correct ack\n");
            return -1;
        }

        // yeah, we got the correct one
        remote_seq = ntohl(tcph->seq); // store the seq_nr locally, we will not use in this sim
        break;
    }

    // send tcp ack with ack = y + 1, seq_nr = ISN + 1
    memset(packet, 0, sizeof(packet));
    generate_tcp_over_ipv4_package(packet, 0, saddr->s_addr, dst->sin_addr.s_addr, SRC_PORT, ntohs(dst->sin_port), ++sequence_number, ++remote_seq, 0, 0, 0, 1,
                                   sizeof(packet) - sizeof(struct iphdr) - sizeof(struct tcphdr));

    if (0 > sendto(fd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) dst, sizeof(struct sockaddr_in))) {
        printf("[-] Cannot send packet TCP ACK\n");
        return -1;
    }

    // connected, handshake done
    return 0;
}

int raw_connect6(int fd, int recv_fd, struct sockaddr_in6 *dst, struct in6_addr *saddr, unsigned short dport) {

    unsigned char packet[2048 + 60] = {0}; // 60 = sizeof(ip6_hdr) + sizeof(tcphdr)
    struct ip6_hdr *iph;
    struct tcphdr *tcph;
    unsigned int remote_seq;

    // send tcp syn with ISN
    generate_tcp_over_ipv6_package(packet, 0, saddr, &dst->sin6_addr, SRC_PORT, dport, sequence_number, 0, 0, 1, 0, 0,
                                   sizeof(packet) - sizeof(struct ip6_hdr) - sizeof(struct tcphdr));

    if (0 > sendto(fd, packet, sizeof(struct ip6_hdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) dst, sizeof(struct sockaddr_in6))) {
        perror("[-] Cannot send packet\n");
        return -1;
    }
    memset(packet, 0, sizeof(packet));

    // wait for tcp syn ack where ack = ISN + 1, seq_nr = y
    while (1) {
        // recv a package on the raw socket
        if (0 > recv(recv_fd, packet, sizeof(packet) - sizeof(struct ip6_hdr) - sizeof(struct tcphdr), 0)) {
            // possibly a timeout occurs
            printf("[-] Cannot recv packet\n");
            return -1;
        }

        // we have received a ipv6 package, check if it is SYN ACK
        iph = (struct ip6_hdr *) packet;
        if (iph->ip6_nxt != IPPROTO_TCP) { // hopefully there are no ipv6 extension headers in our SYN ACK
            printf("[-] Not a TCP packet\n");
            continue;
        }

        tcph = (struct tcphdr *) (packet + sizeof(struct ip6_hdr));

        // we have to skip packets that are not part of our communication
        if (ntohs(tcph->dest) != SRC_PORT || ntohs(tcph->source) != dport)
            continue;

        print_tcp(tcph);
        if (tcph->syn != 1 || tcph->ack != 1 || ntohl(tcph->ack_seq) != sequence_number + 1) {
            printf("[-] Not a TCP SYN ACK packet with correct ack\n");
            return -1;
        }

        // yeah, we got the correct one
        //remote_seq = ntohl(tcph->seq); // store the seq_nr locally, we will not use in this sim*/
        break;
    }

    /*// send tcp ack with ack = y + 1, seq_nr = ISN + 1
    memset(packet, 0, sizeof(packet));
    generate_tcp_over_ipv6_package(packet, 0, saddr, &dst->sin6_addr, SRC_PORT, dport, ++sequence_number, ++remote_seq, 0, 0, 0, 1,
                                   sizeof(packet) - sizeof(struct ip6_hdr) - sizeof(struct tcphdr));

    if (0 > sendto(fd, packet, sizeof(struct ip6_hdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) dst, sizeof(struct sockaddr_in6))) {
        printf("[-] Cannot send packet TCP ACK\n");
        return -1;
    }*/

    // connected, handshake done
    return 0;
}

int sha256(const unsigned char *data, unsigned int len, unsigned char hash[SHA256_DIGEST_LENGTH]) {

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(hash, &sha256);

    return 0;
}

int main(int argc, char *argv[]) {

    char *endptr = NULL;
    struct in_addr ipv4, my_ip4;
    struct in6_addr ipv6, my_ip6;
    unsigned short port, sport;
    char secret[64] = {0};
    char iface[32] = {0};
    unsigned char ip_mode;
    int recv_fd, fd, ret;
    struct sockaddr_in src, dst;
    struct sockaddr_in6 src6, dst6;
    struct timeval tv; // timeout for raw socket recv
    unsigned char secret_hash[SHA256_DIGEST_LENGTH];
    unsigned char second_round_hash[SHA256_DIGEST_LENGTH];
    unsigned char second_round_data[SHA256_DIGEST_LENGTH + 2 * sizeof(unsigned short) + sizeof(struct in6_addr)];
    unsigned int saddr_host;
    size_t len = 0;

    // parse argument
    if (argc != 5) {
        printf("[-] Usage: ./tcp_client <iface_name> <ip> <port> <secret>\n");
        printf("[ ] Example: ./tcp_client en0 ::1 1234 this_is_my_secret_string\n");
        return -1;
    }

    // parse interface
    memcpy(iface, argv[1], sizeof(iface) - 1);

    // parse ip
    if (1 == inet_pton(AF_INET, argv[2], &ipv4)) {
        ip_mode = 4;
    } else if (1 == inet_pton(AF_INET6, argv[2], &ipv6)) {
        ip_mode = 6;
    } else {
        printf("[-] Invalid ip format\n");
        return -1;
    }

    // parse server port
    errno = 0;
    port = (unsigned short) strtol(argv[3], &endptr, 0);

    if (errno != 0  || *endptr != 0) {
        printf("[-] Cannot parse port\n");
        return -1;
    }

    // get my ip via the interface
    ret = ip_mode == 4 ? get_my_ip4(iface, &my_ip4) : get_my_ip6(iface, &my_ip6);
    if (0 > ret) {
        printf("[-] Cannot find interface for source ip\n");
        return -1;
    }

    // parse secret and calculate ISN
    memcpy(secret, argv[4], sizeof(secret) - 1);
    sha256(secret, strlen(secret), secret_hash);
    // calculate the second round hash via sha256(secret_hash | sport | dport | saddr)
    memcpy(second_round_data, secret_hash, sizeof(secret_hash));
    len += sizeof(secret_hash);
    sport = SRC_PORT;
    memcpy(second_round_data + len, &sport, sizeof(unsigned short));
    len += sizeof(unsigned short);
    memcpy(second_round_data + len, &port, sizeof(unsigned short));
    len += sizeof(unsigned short);
    if (ip_mode == 4) {
        saddr_host = ntohl(my_ip4.s_addr);
        memcpy(second_round_data + len, &saddr_host, sizeof(unsigned int));
        len += sizeof(unsigned int);
    } else {
        memcpy(second_round_data + len, &my_ip6, sizeof(struct in6_addr));
        len += sizeof(struct in6_addr);
    }
    sha256(second_round_data, len, second_round_hash);
    memcpy(&sequence_number, second_round_hash, 4);
    // we need it in host byte order
    sequence_number = ntohl(sequence_number);

    // create socket
    if (0 > (fd = socket(ip_mode == 4 ? AF_INET : AF_INET6, SOCK_RAW, IPPROTO_TCP)))  {
        perror("[-] Cannot create raw socket\n");
        return -1;
    }

    // tell the kernel, iphdr is in packet
    if (0 > include_iphdr(fd, ip_mode)) {
        printf("[-] Cannot include ip header into package\n");
        goto out;
    }

    // set a timeout to the socket
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

    if (ip_mode == 4) {
        // this is the server that we want to knock
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = ipv4.s_addr;
        dst.sin_port = htons(port);

        // for bindings
        src.sin_family = AF_INET;
        src.sin_port = htons(SRC_PORT);
        src.sin_addr.s_addr = INADDR_ANY;

        // bind raw socket to SRC_PORT to receive ip responses from the server
        if (0 > bind(fd, (struct sockaddr *) &src, sizeof(struct sockaddr_in))) {
            perror("[-] Cannot bind raw socket");
            goto out;
        }

        // now we can do the handshake
        if (0 > raw_connect(fd, &dst, &my_ip4)) {
            printf("[-] Cannot connect to server. Seems to be closed or filtered\n");
            goto out;
        }
    } else {
        dst6.sin6_family = AF_INET6;
        dst6.sin6_port = 0; // we have to set the dst port to 0, else sendto() failed with -EINVAL
        memcpy(&dst6.sin6_addr, &ipv6, sizeof(struct in6_addr));

        src6.sin6_family = AF_INET6;
        src6.sin6_port = htons(SRC_PORT);
        src6.sin6_addr = in6addr_any;

        //bind raw socket to SRC_PORT to receive ip responses from the server
        if (0 > bind(fd, (struct sockaddr *) &src6, sizeof(struct sockaddr_in6))) {
            perror("[-] Cannot bind raw socket");
            goto out;
        }

        // create a AF_PACKET socket to catch the ipv6 packets
        if (0 > (recv_fd = socket(AF_PACKET, SOCK_DGRAM, htons(0x86dd)))) {
            perror("[-] Cannot create AF_PACKET socket");
            goto out;
        }
        setsockopt(recv_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));

        // now we can do the handshake
        if (0 > raw_connect6(fd, recv_fd, &dst6, &my_ip6, port)) {
            printf("[-] Cannot connect to server. Seems to be closed or filtered\n");
            goto out;
        }

        close(recv_fd);
    }

    printf("Yeah! We have received a TCP SYN ACK. Authorization successful :-)\n");


    // unfortunately we cannot really connect since our OS will response with a
    // TCP RST ACK after receiving the TCP SYN ACK, but it does the job for our purpose

    close(fd);
    return 0;

    out:
    close(recv_fd);
    close(fd);
    return -1;
}