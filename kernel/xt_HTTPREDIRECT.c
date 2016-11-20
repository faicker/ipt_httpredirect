#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include "xt_HTTPREDIRECT.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("faicker.mo@gmail.com");
MODULE_DESCRIPTION("Xtables: http 302 redirect");

static void send_rst(struct sk_buff *oldskb, const struct iphdr *oiph, const struct tcphdr *oth) {
    struct sk_buff *nskb;
    struct iphdr *niph;
    struct tcphdr *tcph;
    struct nf_conn *ct;
    enum ip_conntrack_info ctinfo;

    nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
            LL_MAX_HEADER, GFP_ATOMIC);
    if (!nskb)
        return;

    skb_reserve(nskb, LL_MAX_HEADER);

    skb_reset_network_header(nskb);
    niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
    memcpy(niph, oiph, sizeof(struct iphdr));

    tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
    memcpy(tcph, oth, sizeof(struct tcphdr));
    tcph->ack_seq = 0;
    ((uint8_t *)tcph)[13] = 0;
    tcph->doff    = sizeof(struct tcphdr) / 4;
    tcph->rst    = 1;
    tcph->check = 0;
    tcph->check    = tcp_v4_check(sizeof(struct tcphdr),
            niph->saddr, niph->daddr,
            csum_partial(tcph,
                sizeof(struct tcphdr), 0));

    /* ip_route_me_harder expects skb->dst to be set */
    skb_dst_set(nskb, dst_clone(skb_dst(oldskb)));

    if (ip_route_me_harder(nskb, RTN_UNSPEC)) {
        goto free_nskb;
    }

    nskb->ip_summed = CHECKSUM_NONE;
    /* "Never happens" */
    if (nskb->len > dst_mtu(skb_dst(nskb)))
        goto free_nskb;

    ct = nf_ct_get(oldskb, &ctinfo);
    // for nat
    nskb->nfctinfo = ctinfo;

    ip_local_out(nskb);
    return;

free_nskb:
    kfree_skb(nskb);
}

static void send_redirect_to_client(struct sk_buff *oldskb, const struct iphdr *oiph, const struct tcphdr *oth, const char *payload) {
    struct sk_buff *nskb;
    struct iphdr *niph;
    struct tcphdr *tcph;
    char *p = NULL;
    struct nf_conn *ct;
    enum ip_conntrack_info ctinfo;
    struct sk_buff *rst_skb;

    unsigned int content_length = strlen(payload);

    nskb = alloc_skb(content_length + sizeof(struct iphdr) + sizeof(struct tcphdr) +
            LL_MAX_HEADER, GFP_ATOMIC);
    if (!nskb)
        return;

    skb_reserve(nskb, LL_MAX_HEADER);

    skb_reset_network_header(nskb);
    niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
    niph->version    = 4;
    niph->ihl    = sizeof(struct iphdr) / 4;
    niph->tos    = 0;
    niph->id    = 0;
    niph->frag_off    = htons(IP_DF);
    niph->protocol    = IPPROTO_TCP;
    niph->check    = 0;
    niph->saddr    = oiph->daddr;
    niph->daddr    = oiph->saddr;

    tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
    memset(tcph, 0, sizeof(struct tcphdr));
    tcph->source    = oth->dest;
    tcph->dest    = oth->source;
    tcph->doff    = sizeof(struct tcphdr) / 4;

    if (oth->ack)
        tcph->seq = oth->ack_seq;
    tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
            oldskb->len - ip_hdrlen(oldskb) -
            (oth->doff << 2));
    tcph->ack = 1;
    tcph->fin = 1;

    p = (char *)skb_put(nskb, content_length);
    memcpy(p, payload, content_length);

    tcph->check    = tcp_v4_check(sizeof(struct tcphdr) + content_length,
            niph->saddr, niph->daddr,
            csum_partial(tcph,
                sizeof(struct tcphdr) + content_length, 0));

    /* ip_route_me_harder expects skb->dst to be set */
    skb_dst_set(nskb, dst_clone(skb_dst(oldskb)));

    if (ip_route_me_harder(nskb, RTN_UNSPEC))
        goto free_nskb;

    niph->ttl    = dst_metric(skb_dst(nskb), RTAX_HOPLIMIT);
    nskb->ip_summed = CHECKSUM_NONE;

    /* "Never happens" */
    if (nskb->len > dst_mtu(skb_dst(nskb)))
        goto free_nskb;

    ct = nf_ct_get(oldskb, &ctinfo);
    // for nat
    ctinfo = IP_CT_IS_REPLY;
    nskb->nfctinfo = ctinfo;

    ip_local_out(nskb);
    return;

free_nskb:
    kfree_skb(nskb);
}

static const char *content_format = "HTTP/1.1 302 Found\r\nLocation: %s\r\n\r\n";

static void http_redirect(struct sk_buff *oldskb, int hook, const char *url) {
    const struct iphdr *oiph;
    const struct tcphdr *oth;
    struct tcphdr _otcph;
    char payload[256];

    /* IP header checks: fragment. */
    if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET))
        return;

    oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
            sizeof(_otcph), &_otcph);
    if (oth == NULL)
        return;

    /* No RST for RST. */
    if (oth->rst)
        return;

    if (skb_rtable(oldskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
        return;

    /* Check checksum */
    if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
        return;
    oiph = ip_hdr(oldskb);

    snprintf(payload, sizeof(payload), content_format, url);
    send_redirect_to_client(oldskb, oiph, oth, payload);
    // rst to server
    send_rst(oldskb, oiph, oth);
}

static unsigned int
httpredirect_tg(struct sk_buff *skb, const struct xt_target_param *par)
{
    const struct xt_httpredirect_info *httpredirect = par->targinfo;
    pr_debug("redirect url is %s\n", httpredirect->url);
    http_redirect(skb, par->hooknum, httpredirect->url);
    return NF_DROP;
}

static bool httpredirect_tg_check(const struct xt_tgchk_param *par)
{
    const struct ipt_entry *e = par->entryinfo;

    /* Must specify that it's a TCP packet */
    if (e->ip.proto != IPPROTO_TCP
            || (e->ip.invflags & XT_INV_PROTO)) {
        printk("xt_HTTPREDIRECT: HTTPREDIRECT invalid for non-tcp\n");
        return false;
    }
    return true;
}

static struct xt_target httpredirect_tg_reg __read_mostly = {
    .name        = "HTTPREDIRECT",
    .family        = NFPROTO_IPV4,
    .target        = httpredirect_tg,
    .targetsize    = sizeof(struct xt_httpredirect_info),
    .table        = "filter",
    .hooks        = 1 << NF_INET_FORWARD,
    .checkentry    = httpredirect_tg_check,
    .me        = THIS_MODULE,
};

static int __init httpredirect_tg_init(void)
{
    return xt_register_target(&httpredirect_tg_reg);
}

static void __exit httpredirect_tg_exit(void)
{
    xt_unregister_target(&httpredirect_tg_reg);
}

module_init(httpredirect_tg_init);
module_exit(httpredirect_tg_exit);
