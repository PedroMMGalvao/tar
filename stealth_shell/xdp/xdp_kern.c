// SPDX-License-Identifier: GPL-2.0
//
// xdp_kern.c — eBPF/XDP kernel-side program — canal encoberto L2 puro.
//
// Filtra por EtherType 0x88B5 + magic "STLH" + replay protection.
// Redireciona para AF_XDP sempre com chave 0 (queue 0 forçada).

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define STEALTH_ETHERTYPE  0x88B5u
#define STEALTH_MAGIC  0x484C5453u  // "STLH" little-endian

struct stealth_hdr {
    __u8  magic[4];
    __u32 seq;
} __attribute__((packed));

// XSKMAP — queue index → AF_XDP socket fd
struct {
    __uint(type,        BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key,   __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// LRU hash — replay protection
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u32);
    __type(value, __u8);
} replay_map SEC(".maps");

// Contadores: index 0 = matched, index 1 = replay drops
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key,   __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

static __always_inline void stats_inc(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&stats_map, &idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);
}

SEC("xdp")
int xdp_stealth_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // ── Ethernet ──────────────────────────────────────────────────────
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    bpf_printk("XDP mac2: EtherType=0x%x\n", bpf_ntohs(eth->h_proto));

    // Só frames com o nosso EtherType — todo o resto (ARP, IPv4, …) passa
     if (bpf_ntohs(eth->h_proto) != STEALTH_ETHERTYPE) {
        bpf_printk("XDP: EtherType 0x%x — PASS\n", bpf_ntohs(eth->h_proto));
        return XDP_PASS;
    }
    // Imprime o MAC de origem do header Ethernet exterior
    bpf_printk("XDP RX: outer_src=%02x:%02x:%02x:%02x:%02x:%02x\n",
            eth->h_source[0], eth->h_source[1], eth->h_source[2],
            eth->h_source[3], eth->h_source[4], eth->h_source[5]);

    // ── Stealth header ────────────────────────────────────────────────
    struct stealth_hdr *hdr = (void *)(eth + 1);
    
    if ((void *)(hdr + 1) > data_end)
        return XDP_PASS;
    
  

    // Magic check — segunda camada de filtragem
    __u32 magic;
    __builtin_memcpy(&magic, hdr->magic, 4);
    if (magic != STEALTH_MAGIC)
        return XDP_PASS;
    
    bpf_printk("XDP: STEALTH frame matched, seq=%u\n", bpf_ntohl(hdr->seq));

    // ── Replay protection ─────────────────────────────────────────────
    __u32 seq = bpf_ntohl(hdr->seq);
    __u8 *seen = bpf_map_lookup_elem(&replay_map, &seq);
    if (seen) {
        stats_inc(1);
        return XDP_DROP;
    }
    __u8 val = 1;
    bpf_map_update_elem(&replay_map, &seq, &val, BPF_NOEXIST);

    // ── Redirect para AF_XDP (sempre chave 0 — queue 0) ──────────────
    // XDP_DROP como fallback: se o socket não estiver registado, dropa
    // silenciosamente em vez de fazer XDP_PASS ao kernel.
    stats_inc(0);
    return bpf_redirect_map(&xsks_map, 0, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
