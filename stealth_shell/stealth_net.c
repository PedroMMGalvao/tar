/**
 * @file stealth_net.c
 * @brief Implementações de baixo nível para orquestração de rings AF_XDP e carregamento eBPF.
 */

#include "stealth_net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <linux/bpf.h>

#define BPF_OBJ_PATH  "xdp/xdp_prog.o"
#define BPF_PROG_NAME "xdp_stealth_filter"
#define BPF_MAP_NAME  "xsks_map"

/**
 * @brief Gera um endereço MAC pseudo-aleatório através do /dev/urandom.
 * * Aplica as máscaras de bits necessárias para garantir que o MAC gerado está em
 * conformidade com as regras de endereço Unicast Localmente Administrado (ULA).
 * * @param mac Buffer de 6 bytes de saída para o endereço MAC.
 */
static void generate_random_mac(uint8_t *mac)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t n = fread(mac, 1, 6, f);
        if (n != 6) memset(mac, 0xAB, 6);
        fclose(f);
    }
    mac[0] = (mac[0] & 0xFE) | 0x02;   // locally administered, unicast
}

/**
 * @brief Callback costumizado para supressão de mensagens informativas da libbpf.
 * @param level Nível de verbosidade do log detetado.
 * @param fmt String de formatação padrão print.
 * @param ap Lista de argumentos variáveis.
 * @return Retorna a saída padrão de erro apenas se for um aviso (LIBBPF_WARN).
 */
static int libbpf_quiet(enum libbpf_print_level level,
                        const char *fmt, va_list ap)
{
    if (level == LIBBPF_WARN) return vfprintf(stderr, fmt, ap);
    return 0;
}

struct xsk_info *init_xsk_socket(const char *ifname)
{
    libbpf_set_print(libbpf_quiet);

    struct xsk_info *xsk = calloc(1, sizeof(*xsk));
    if (!xsk) return NULL;

    xsk->ifindex = (int)if_nametoindex(ifname);
    if (!xsk->ifindex) {
        fprintf(stderr, "[!] Interface '%s' not found: %s\n",
                ifname, strerror(errno));
        goto err_free;
    }

    struct bpf_object *obj = bpf_object__open(BPF_OBJ_PATH);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[!] Failed to open '%s'\n", BPF_OBJ_PATH);
        goto err_free;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "[!] Failed to load BPF object\n");
        bpf_object__close(obj);
        goto err_free;
    }
    xsk->bpf_obj = obj;

    struct bpf_program *prog =
    bpf_object__find_program_by_name(obj, BPF_PROG_NAME);
    if (!prog) {
        fprintf(stderr, "[!] BPF program '%s' not found\n", BPF_PROG_NAME);
        goto err_close_obj;
    }
    xsk->prog_fd = bpf_program__fd(prog);

    bpf_xdp_detach(xsk->ifindex, XDP_FLAGS_DRV_MODE, NULL);
    bpf_xdp_detach(xsk->ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_xdp_detach(xsk->ifindex, XDP_FLAGS_HW_MODE,  NULL);

    usleep(100000);  // 100ms

    int ret = bpf_xdp_attach(xsk->ifindex, xsk->prog_fd,
                            XDP_FLAGS_DRV_MODE, NULL);
    if (ret < 0) {
        fprintf(stderr, "[!] Native XDP attach failed: %s\n", strerror(-ret));
        goto err_close_obj;
    }
    xsk->xdp_flags = XDP_FLAGS_DRV_MODE;

    uint32_t attached_id = 0;
    bpf_xdp_query_id(xsk->ifindex, XDP_FLAGS_DRV_MODE, &attached_id);
    struct bpf_prog_info info = {};
    uint32_t info_len2 = sizeof(info);
    bpf_obj_get_info_by_fd(xsk->prog_fd, &info, &info_len2); 
    fprintf(stdout, "[+] XDP NATIVE em '%s' — prog_id nosso=%u anexado=%u %s\n",
            ifname, info.id, attached_id,
            (info.id == attached_id) ? "✓" : "← MISMATCH!");

    if (info.id != attached_id) {
        fprintf(stderr, "[!] Programa errado anexado. Corre: sudo pkill -f stealth_shell_xdp && sudo ./stealth_setup.sh\n");
        goto err_close_obj;
    }

    size_t buf_size = (size_t)NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&xsk->buffer, getpagesize(), buf_size)) {
        fprintf(stderr, "[!] posix_memalign failed\n");
        goto err_detach;
    }

    struct xsk_umem_config ucfg = {
        .fill_size      = NUM_FRAMES,
        .comp_size      = NUM_FRAMES,
        .frame_size     = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    };
    if (xsk_umem__create(&xsk->umem, xsk->buffer, buf_size,
                         &xsk->fq, &xsk->cq, &ucfg)) {
        fprintf(stderr, "[!] xsk_umem__create failed\n");
        goto err_free_buf;
    }

    struct xsk_socket_config scfg = {
        .rx_size      = NUM_FRAMES,
        .tx_size      = NUM_FRAMES,
        .xdp_flags    = XDP_FLAGS_DRV_MODE,
        .bind_flags   = XDP_ZEROCOPY,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
    };
    if (xsk_socket__create(&xsk->xsk, ifname, 0,
                           xsk->umem, &xsk->rx, &xsk->tx, &scfg)) {
        fprintf(stderr, "[!] xsk_socket__create failed on '%s'\n", ifname);
        goto err_umem;
    }
    fprintf(stdout, "[+] AF_XDP socket: NATIVE + ZERO-COPY on '%s'\n", ifname);

    struct bpf_xdp_attach_opts query_opts = { .sz = sizeof(query_opts) };
    uint32_t attached_prog_id = 0;
    bpf_xdp_query_id(xsk->ifindex, XDP_FLAGS_DRV_MODE, &attached_prog_id);

    uint32_t our_prog_id = 0;
    struct bpf_prog_info prog_info = {};
    uint32_t info_len = sizeof(prog_info);
    bpf_obj_get_info_by_fd(xsk->prog_fd, &prog_info, &info_len);
    our_prog_id = prog_info.id;

    fprintf(stdout, "[+] Programa anexado id=%u | Nosso id=%u\n",
            attached_prog_id, our_prog_id);

    if (attached_prog_id != our_prog_id) {
        fprintf(stderr, "[!] Programa errado anexado à interface!\n"
                        "    Corre: sudo ./stealth_setup.sh\n");
        goto err_socket;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, BPF_MAP_NAME);
    if (!map) {
        fprintf(stderr, "[!] BPF map '%s' not found\n", BPF_MAP_NAME);
        goto err_socket;
    }
    xsk->map_fd = bpf_map__fd(map);

    uint32_t key  = 0;
    int      sock = xsk_socket__fd(xsk->xsk);
    if (bpf_map_update_elem(xsk->map_fd, &key, &sock, BPF_ANY)) {
        fprintf(stderr, "[!] xsks_map update failed: %s\n", strerror(errno));
        goto err_socket;
    }
    fprintf(stdout, "[+] Socket fd=%d registado em xsks_map[0]\n", sock);

    uint32_t idx;
    uint32_t rx_frames = NUM_FRAMES / 2;
    if (xsk_ring_prod__reserve(&xsk->fq, rx_frames, &idx) == rx_frames) {
        for (uint32_t i = 0; i < rx_frames; i++)
            *xsk_ring_prod__fill_addr(&xsk->fq, idx + i) =
                (uint64_t)i * FRAME_SIZE;
        xsk_ring_prod__submit(&xsk->fq, rx_frames);
    } else {
        fprintf(stderr, "[!] Fill ring reserve failed\n");
        goto err_socket;
    }
    xsk->tx_frame_idx = NUM_FRAMES / 2;

    fprintf(stdout, "[+] UMEM: %u frames RX | %u frames TX\n",
            rx_frames, rx_frames);

    return xsk;

err_socket:    xsk_socket__delete(xsk->xsk);
err_umem:      xsk_umem__delete(xsk->umem);
err_free_buf:  free(xsk->buffer);
err_detach:    bpf_xdp_detach(xsk->ifindex, XDP_FLAGS_DRV_MODE, NULL);
err_close_obj: bpf_object__close(xsk->bpf_obj);
err_free:      free(xsk);
               return NULL;
}

void cleanup_xsk_socket(struct xsk_info *xsk, const char *ifname)
{
    (void)ifname;
    if (!xsk) return;
    xsk_socket__delete(xsk->xsk);
    xsk_umem__delete(xsk->umem);
    free(xsk->buffer);
    bpf_xdp_detach(xsk->ifindex, xsk->xdp_flags, NULL);
    bpf_object__close(xsk->bpf_obj);
    free(xsk);
}

int xsk_send_packet(struct xsk_info *xsk, stealth_pkt_t *pkt)
{   uint8_t r_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint32_t idx;
    if (xsk_ring_prod__reserve(&xsk->tx, 1, &idx) < 1)
        return -1;

    uint64_t addr = xsk->tx_frame_idx * FRAME_SIZE;
    xsk->tx_frame_idx++;
    if (xsk->tx_frame_idx >= NUM_FRAMES)
        xsk->tx_frame_idx = NUM_FRAMES / 2;

    uint32_t cq_idx;
    unsigned int completed = xsk_ring_cons__peek(&xsk->cq, 1, &cq_idx);
    if (completed > 0) xsk_ring_cons__release(&xsk->cq, completed);

    uint8_t *frame = xsk_umem__get_data(xsk->buffer, addr);

    struct ethhdr *eth = (struct ethhdr *)frame;
    generate_random_mac(eth->h_source);
    memcpy(eth->h_dest, r_mac, 6);
    eth->h_proto = htons(STEALTH_ETHERTYPE);

    memcpy(frame + ETH_HDR_LEN, pkt, sizeof(stealth_pkt_t));

    uint32_t total = ETH_HDR_LEN + sizeof(stealth_pkt_t);
    xsk_ring_prod__tx_desc(&xsk->tx, idx)->addr = addr;
    xsk_ring_prod__tx_desc(&xsk->tx, idx)->len  = total;
    xsk_ring_prod__submit(&xsk->tx, 1);

    if (xsk_ring_prod__needs_wakeup(&xsk->tx))
        sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    return 0;
}

int xsk_receive_packet(struct xsk_info *xsk, stealth_pkt_t *pkt)
{
    uint32_t idx;
    if (!xsk_ring_cons__peek(&xsk->rx, 1, &idx))
        return 0;
    uint64_t addr  = xsk_ring_cons__rx_desc(&xsk->rx, idx)->addr;
    uint32_t len   = xsk_ring_cons__rx_desc(&xsk->rx, idx)->len;
    uint8_t *frame = xsk_umem__get_data(xsk->buffer, addr);

    if (len >= ETH_HDR_LEN + sizeof(stealth_pkt_t))
        memcpy(pkt, frame + ETH_HDR_LEN, sizeof(stealth_pkt_t));

    xsk_ring_cons__release(&xsk->rx, 1);

    uint32_t f_idx;
    if (xsk_ring_prod__reserve(&xsk->fq, 1, &f_idx) == 1) {
        *xsk_ring_prod__fill_addr(&xsk->fq, f_idx) = addr;
        xsk_ring_prod__submit(&xsk->fq, 1);
    }

    return 1;
}