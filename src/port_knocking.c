#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include "port_knocking.h"
#include "helper.h"

/**
 *  Port knocking ensures that all TCP ports are hidden, i.e. filtered in such a way that unauthorized clients, such as
 *  a nmap port scan, cannot connect to the filtered port and do not receive any response on tcp packets addressed to
 *  the protected port.
 *
 *  Authorization is done by setting the ISN (Initial seq. number of TCP SYN) to a specific value:
 *  ISN = SHA256(SHA256(shared_secret) | SRC_PORT | DST_PORT | SRC_IP)
 *
 *  The shared secret is responsible for the authorization (proving the knowledge of a secret).
 *  The routing information (Ports + src IP) are responsible for avoiding sniffers to capture the secret.
 *
 *  We use netfilter hooks (PRE_ROUTING) for handling incoming TCP packets.
 *  If a packet comes from an unauthorized client it will be dropped, except for TCP SYN with valid ISN.
 *  If a TCP SYN with valid ISN is received, we will store the clients address (IP + port) and will mark this
 *  as an authorized client with open connection, such that we can accept all the incoming traffic from this client.
 *
 *  If we receive a TCP RST or TCP FIN from a client, we will remove the client from the authorized clients list.
 *  Further, we check outgoing traffic via LOCAL_OUT filtering, such that we can also catch outgoing TCP RST, TCP FIN
 *  to authorized clients. In this way we are also able to remove connections when our system terminates the connection.
 */

static int enabled = 0;

static struct nf_hook_ops *nfho_v4 = NULL;
static struct nf_hook_ops *nfho_v6 = NULL;
static struct nf_hook_ops *nfho_v4_out = NULL;
static struct nf_hook_ops *nfho_v6_out = NULL;

/*
 * Data structures for connections
 */
struct ipv4_connection {
    struct list_head list;
    unsigned short port;
    unsigned int ip;
};

static struct ipv4_connection *check_ipv4_connection(unsigned short port, unsigned int ip, struct list_head *connections) {

    struct ipv4_connection *connection;

    list_for_each_entry(connection, connections, list) {
        if (connection->port == port && connection->ip == ip) {
            return connection;
        }
    }

    return NULL;
}

struct ipv6_connection {
    struct list_head list;
    unsigned short port;
    struct in6_addr ip;
};

static struct ipv6_connection *check_ipv6_connection(unsigned short port, struct in6_addr *ip, struct list_head *connections) {

    struct ipv6_connection *connection;
    int i = 0;

    list_for_each_entry(connection, connections, list) {

        for (i = 0; i < 16; i++) {
            if (connection->ip.s6_addr[i] != ip->s6_addr[i]) {
                return NULL;
            }
        }

        if (connection->port == port) {
            return connection;
        }
    }

    return NULL;
}

/*
 * Data structures for hidden ports
 */
static DEFINE_RWLOCK(ports_lock);
static LIST_HEAD(hidden_ports);

struct port_knocking_node {
    struct list_head list;
    unsigned short port;    // knocked port
    unsigned char hash[32]; // sha256 of secret

    // lists for ipv4 and ipv6 connections
    struct list_head ipv4_connections;
    struct list_head ipv6_connections;
};

static void destroy_port_node(struct port_knocking_node *node) {

    struct ipv4_connection *entry4, *tmp4;
    struct ipv6_connection *entry6, *tmp6;

    if (node != NULL) {

        list_for_each_entry_safe(entry4, tmp4, &node->ipv4_connections, list) {
            list_del(&entry4->list);
            kfree(entry4);
        }

        list_for_each_entry_safe(entry6, tmp6, &node->ipv6_connections, list) {
            list_del(&entry6->list);
            kfree(entry6);
        }

        kfree(node);
    }
}

static struct port_knocking_node *create_port_node(unsigned short port) {

    struct port_knocking_node *node;
    if (NULL == (node = kmalloc(sizeof(struct port_knocking_node), GFP_KERNEL))) {
        return NULL;
    }

    INIT_LIST_HEAD(&node->ipv4_connections);
    INIT_LIST_HEAD(&node->ipv6_connections);

    node->port = port;
    return node;
}

/*
 * Check if port is hidden
 *
 * Expects read lock
 */
static struct port_knocking_node *is_hidden(unsigned short port) {

    struct port_knocking_node *entry;
    list_for_each_entry(entry, &hidden_ports, list) {
        if (entry->port == port) {
            return entry;
        }
    }
    return NULL;
}

static unsigned int check_out_packet(unsigned char ip_version, struct tcphdr *tcph, unsigned int daddr_v4, struct in6_addr *daddr_v6) {

    struct port_knocking_node *existent_node;
    struct ipv4_connection *c;
    struct ipv6_connection *c6;

    /*
     * We have received an outgoing TCP packet, do the following:
     * - check if it is TCP RST or TCP FIN, if not accept
     * - check if src port is hidden, if not accept
     * - check if client (dest port + dst addr) is authorized, if not then drop (should never happen!)
     * - remove the authorized client from the list of authorized clients
     */

    if (tcph->rst || tcph->fin) {

        // check if src port is hidden
        write_lock(&ports_lock);
        if (NULL == (existent_node = is_hidden(ntohs(tcph->source)))) {
            // not hidden
            goto label_accept;
        }

        // hidden, remove if authorized
        if (ip_version == 4) {
            if (NULL == (c = check_ipv4_connection(ntohs(tcph->dest), daddr_v4, &existent_node->ipv4_connections))) {
                // non authorized
                goto label_drop;
            } else {
                // remove client
                list_del(&c->list);
                goto label_accept;
            }
        } else {
            if (NULL == (c6 = check_ipv6_connection(ntohs(tcph->dest), daddr_v6, &existent_node->ipv6_connections))) {
                // non authorized
                goto label_drop;
            } else {
                // remove client
                list_del(&c6->list);
                goto label_accept;
            }
        }
    }
    // not a TCP SYN / TCP ACK

label_accept:
    write_unlock(&ports_lock);
    return NF_ACCEPT;

label_drop:
    write_unlock(&ports_lock);
    return NF_DROP;
}

static unsigned int check_packet(unsigned char ip_version, struct tcphdr *tcph, unsigned int saddr_v4, struct in6_addr *saddr_v6) {

    unsigned int seqnr;
    struct port_knocking_node *existent_node;
    struct ipv4_connection *c, *new_c;
    struct ipv6_connection *c6, *new_c6;

    /*
     * We have received a TCP packet, we have to do the following steps:
     *  - check if the dport is hidden. If not then accept
     *  - check if the source (ip + port) is already authorized, then accept and check if it is FIN or RESET, so we can
     *    remove from open connections
     *  - check if it is TCP SYN, if not TCP SYN then DROP since we have a non-authorized non SYN packet,
     *    maybe a special nmap scan. We want nmap to think it is filtered or closed for every scan
     *  - check if ISN is the hashed secret. If so then accept and insert in connections, else DROP
     */

    write_lock(&ports_lock);
    if (NULL == (existent_node = is_hidden(ntohs(tcph->dest)))) {
        // not hidden
        goto label_accept;
    }

    if (ip_version == 4) {
        c = check_ipv4_connection(ntohs(tcph->source), saddr_v4, &existent_node->ipv4_connections);
    } else {
        c6 = check_ipv6_connection(ntohs(tcph->source), saddr_v6, &existent_node->ipv6_connections);
    }

    if ((ip_version == 4 && c != NULL) || (ip_version == 6 && c6 != NULL)) {
        // already authorized
        if (tcph->rst || tcph->fin) {
            if (ip_version == 4) {
                list_del(&c->list);
                kfree(c);
            } else {
                list_del(&c6->list);
                kfree(c6);
            }
        }
        goto label_accept;
    }

    if (tcph->syn && !tcph->ack) {
        unsigned int hash;
        unsigned char second_round_hash_data[32 + 2 + 2 + 16]; //32 byte of sha256 hash + 4 byte ports + 16 byte saddr
        unsigned char second_round_hash[32];
        unsigned short sport, dport;
        size_t len = 0;

        // we got a TCP SYN
        seqnr = ntohl(tcph->seq);

        // calculate second round hash
        memcpy(second_round_hash_data, existent_node->hash, sizeof(existent_node->hash));
        len += sizeof(existent_node->hash);
        sport = ntohs(tcph->source);
        memcpy(second_round_hash_data + len, &sport, sizeof(unsigned short));
        len += sizeof(unsigned short);
        dport = ntohs(tcph->dest);
        memcpy(second_round_hash_data + len, &dport, sizeof(unsigned short));
        len += sizeof(unsigned short);
        if (ip_version == 4) {
            memcpy(second_round_hash_data + len, &saddr_v4, sizeof(unsigned int));
            len += sizeof(unsigned int);
        } else {
            memcpy(second_round_hash_data + len, saddr_v6, sizeof(struct in6_addr));
            len += sizeof(struct in6_addr);
        }

        if (0 != sha256(second_round_hash_data, len, second_round_hash)) {
            goto label_drop;
        }

        memcpy(&hash, second_round_hash, 4); // truncate first 4 bytes

        if (seqnr == ntohl(hash)) {
            // authorization successful, add into open connections
            if (ip_version == 4) {
                new_c = kmalloc(sizeof(struct ipv4_connection), GFP_KERNEL);
                if (new_c) {
                    new_c->port = ntohs(tcph->source);
                    new_c->ip = saddr_v4;
                    list_add_tail(&new_c->list, &existent_node->ipv4_connections);
                }
            } else {
                new_c6 = kmalloc(sizeof(struct ipv6_connection), GFP_KERNEL);
                if (new_c6) {
                    new_c6->port = ntohs(tcph->source);
                    memcpy(&new_c6->ip, saddr_v6, sizeof(struct in6_addr));
                    list_add_tail(&new_c6->list, &existent_node->ipv6_connections);
                }
            }
            goto label_accept;
        } else {
            // authorization failed
            goto label_drop;
        }
    } else {
        // other TCP packet
        goto label_drop;
    }

label_accept:
    write_unlock(&ports_lock);
    return NF_ACCEPT;

label_drop:
    write_unlock(&ports_lock);
    return NF_DROP;
}

static unsigned int ipv4_hook_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        return check_out_packet(4, tcph, ntohl(iph->daddr), NULL);
    }

    return NF_ACCEPT; // no tcp
}

static unsigned int ipv6_hook_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct ipv6hdr *iph6;
    struct tcphdr *tcph;

    if (!skb)
        return NF_ACCEPT;

    iph6 = ipv6_hdr(skb);

    if (iph6->nexthdr == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        return check_out_packet(6, tcph, 0, &iph6->daddr);
    }

    return NF_ACCEPT; // no tcp
}

static unsigned int ipv4_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (!skb)
        return NF_ACCEPT;


    iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        return check_packet(4, tcph, ntohl(iph->saddr), NULL);
    }

    return NF_ACCEPT; // no tcp
}

static unsigned int ipv6_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct ipv6hdr *iph6;
    struct tcphdr *tcph;

    if (!skb)
        return NF_ACCEPT;

    iph6 = ipv6_hdr(skb);

    if (iph6->nexthdr == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        return check_packet(6, tcph, 0, &iph6->saddr);
    }

    return NF_ACCEPT; // no tcp
}

/*
 * Hide a port
 */
int port_knocking_add(struct hidden_port data) {

    int ret = -1;
    struct port_knocking_node *new_entry;

    if (enabled) {

        write_lock(&ports_lock);

        /* check if already hidden */
        if (is_hidden(data.port) == NULL) {

            // create new entry
            if (NULL == (new_entry = create_port_node(data.port))) {
                goto locked_err;
            }

            // create hash
            if (0 > sha256(data.secret, strlen(data.secret), new_entry->hash)) {
                goto locked_err;
            }

            // allocate new struct and insert data
            list_add_tail(&new_entry->list, &hidden_ports);
            ret = 0;
        }

        write_unlock(&ports_lock);
    }

    return ret;

locked_err:
    destroy_port_node(new_entry);
    write_unlock(&ports_lock);
    return -1;
}

int port_knocking_rm(unsigned short port) {

    struct port_knocking_node *entry;
    int ret = -1;

    if (enabled) {

        write_lock(&ports_lock);

        /* Remove port from list and free memory */
        if ((entry = is_hidden(port)) != NULL) {
            list_del(&entry->list);
            destroy_port_node(entry);
            ret = 0;
        }

        write_unlock(&ports_lock);
    }

    return ret;

}

int enable_port_knocking(void) {

    // ipv4 hook
    nfho_v4 = (struct nf_hook_ops*) kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);

    nfho_v4->hook = (nf_hookfn*) ipv4_hook;		// hook
    nfho_v4->hooknum = NF_INET_PRE_ROUTING;     // received packets
    nfho_v4->pf = PF_INET;			            // IPv4
    nfho_v4->priority = NF_IP_PRI_FIRST;		// max priority

    nf_register_net_hook(&init_net, nfho_v4);

    // ipv6 hook
    nfho_v6 = (struct nf_hook_ops*) kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);

    nfho_v6->hook = (nf_hookfn*) ipv6_hook;		// hook
    nfho_v6->hooknum = NF_INET_PRE_ROUTING;     // received packets
    nfho_v6->pf = PF_INET6;			            // IPv6
    nfho_v6->priority = NF_IP_PRI_FIRST;		// max priority

    nf_register_net_hook(&init_net, nfho_v6);

    // ipv4 hook out
    nfho_v4_out = (struct nf_hook_ops*) kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);

    nfho_v4_out->hook = (nf_hookfn*) ipv4_hook_out;	// hook
    nfho_v4_out->hooknum = NF_INET_LOCAL_OUT;       // outgoing
    nfho_v4_out->pf = PF_INET;			            // IPv4
    nfho_v4_out->priority = NF_IP_PRI_FIRST;		// max priority

    nf_register_net_hook(&init_net, nfho_v4_out);

    // ipv6 hook out
    nfho_v6_out = (struct nf_hook_ops*) kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);

    nfho_v6_out->hook = (nf_hookfn*) ipv6_hook_out;	// hook
    nfho_v6_out->hooknum = NF_INET_LOCAL_OUT;       // outgoing
    nfho_v6_out->pf = PF_INET6;			            // IPv6
    nfho_v6_out->priority = NF_IP_PRI_FIRST;		// max priority

    nf_register_net_hook(&init_net, nfho_v6_out);

    enabled = 1;
    return 0;
}

void disable_port_knocking(void) {

    struct port_knocking_node *entry, *tmp;

    enabled = 0;

    nf_unregister_net_hook(&init_net, nfho_v4);
    kfree(nfho_v4);

    nf_unregister_net_hook(&init_net, nfho_v6);
    kfree(nfho_v6);

    nf_unregister_net_hook(&init_net, nfho_v4_out);
    kfree(nfho_v4_out);

    nf_unregister_net_hook(&init_net, nfho_v6_out);
    kfree(nfho_v6_out);

    /*
     * Remove all hidden ports from list
     */
    write_lock(&ports_lock);
    list_for_each_entry_safe(entry, tmp, &hidden_ports, list) {
        list_del(&entry->list);
        destroy_port_node(entry);
    }
    write_unlock(&ports_lock);

}