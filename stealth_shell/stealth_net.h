#ifndef STEALTH_NET_H
#define STEALTH_NET_H

#include <stdint.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

// ─── Protocol constants ────────────────────────────────────────────────────
#define STEALTH_ETHERTYPE  0x88B5
#define STEALTH_MAGIC      "STLH"

// ─── Frame layout (fixed 256-byte stealth_pkt_t) ──────────────────────────
// Offset  Size  Field
//  0       6    dst_mac
//  6       6    src_mac
// 12       4    magic          "STLH"
// 16       4    seq            número de sequência (big-endian)
// 20       2    payload_len    comprimento do plaintext (≤ MAX_PAYLOAD)
// 22      16    iv             AES-256-CTR IV (aleatório por pacote)
// 38     186    payload        ciphertext AES-256-CTR
// 224     32    hmac           HMAC-SHA256(iv ‖ ciphertext)
// Total  256 bytes
#define IV_SIZE      16
#define HMAC_SIZE    32
#define MAX_PAYLOAD  198

typedef struct __attribute__((packed)) {
    char     magic[4];
    uint32_t seq;
    uint16_t payload_len;
    uint8_t  iv[IV_SIZE];
    uint8_t  payload[MAX_PAYLOAD];
    uint8_t  hmac[HMAC_SIZE];
} stealth_pkt_t;

_Static_assert(sizeof(stealth_pkt_t) == 256,
               "stealth_pkt_t must be exactly 256 bytes");

// Wire: Ethernet (14) + stealth_pkt_t (256) = 270 bytes
#define ETH_HDR_LEN  14

// ─── AF_XDP sizing ────────────────────────────────────────────────────────
#define NUM_FRAMES  2048
#define FRAME_SIZE  XSK_UMEM__DEFAULT_FRAME_SIZE

// ─── AF_XDP socket context ────────────────────────────────────────────────
struct xsk_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem     *umem;
    void                *buffer;
    struct xsk_socket   *xsk;
    struct bpf_object   *bpf_obj;
    int                  ifindex;
    int                  prog_fd;
    int                  map_fd;
    uint32_t             xdp_flags;
    uint64_t             tx_frame_idx;  // próximo frame TX (segunda metade UMEM)
};

// ─── API ───────────────────────────────────────────────────────────────────
struct xsk_info *init_xsk_socket(const char *ifname);
void             cleanup_xsk_socket(struct xsk_info *xsk, const char *ifname);
int              xsk_send_packet(struct xsk_info *xsk, stealth_pkt_t *pkt);
int              xsk_receive_packet(struct xsk_info *xsk, stealth_pkt_t *pkt);

#endif /* STEALTH_NET_H */
