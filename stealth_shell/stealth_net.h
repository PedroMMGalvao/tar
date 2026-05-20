/**
 * @file stealth_net.h
 * @brief Definições de rede e estruturas de dados para o socket AF_XDP do Stealth Shell.
 * @author Pedro Galvão
 * @date 2026
 */

#ifndef STEALTH_NET_H
#define STEALTH_NET_H

#include <stdint.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

/** @brief EtherType customizado para tráfego stealth (Protocolo experimental/local) */
#define STEALTH_ETHERTYPE  0x88B5

/** @brief Magic bytes para validação inicial de pacotes stealth */
#define STEALTH_MAGIC      "STLH"

#define IV_SIZE      16   /**< Tamanho do IV para AES-256-CTR */
#define HMAC_SIZE    32   /**< Tamanho do buffer HMAC-SHA256 */
#define MAX_PAYLOAD  198  /**< Espaço máximo para texto limpo (plaintext) */

/**
 * @struct stealth_pkt_t
 * @brief Estrutura de dados empacotada que define o layout do frame Stealth na camada 2.
 * * O tamanho total desta estrutura é rigidamente fixado em 256 bytes através de asserção estática.
 */
typedef struct __attribute__((packed)) {
    char     magic[4];               /**< Identificador do protocolo "STLH" */
    uint32_t seq;                     /**< Número de sequência (Big-Endian) para evitar replay attacks */
    uint16_t payload_len;             /**< Comprimento real do payload cifrado */
    uint8_t  iv[IV_SIZE];             /**< Vetor de Inicialização gerado aleatoriamente por pacote */
    uint8_t  payload[MAX_PAYLOAD];    /**< Dados cifrados contendo a payload do comando/resposta */
    uint8_t  hmac[HMAC_SIZE];         /**< Tag de autenticação HMAC-SHA256(iv || ciphertext) */
} stealth_pkt_t;

_Static_assert(sizeof(stealth_pkt_t) == 256,
               "stealth_pkt_t must be exactly 256 bytes");

/** @brief Comprimento fixo do cabeçalho Ethernet standard */
#define ETH_HDR_LEN  14

#define NUM_FRAMES  2048                            /**< Número total de buffers alocados no UMEM */
#define FRAME_SIZE  XSK_UMEM__DEFAULT_FRAME_SIZE    /**< Tamanho padrão de cada frame no UMEM (normalmente 4KB) */

/**
 * @struct xsk_info
 * @brief Contexto operacional e rings de controlo associados ao socket AF_XDP.
 */
struct xsk_info {
    struct xsk_ring_cons rx;           /**< Ring de consumo para pacotes recebidos (RX) */
    struct xsk_ring_prod tx;           /**< Ring de produção para envio de pacotes (TX) */
    struct xsk_ring_prod fq;           /**< Fill Ring: passa buffers livres do userspace para o kernel */
    struct xsk_ring_cons cq;           /**< Completion Ring: indica buffers já transmitidos pelo kernel */
    struct xsk_umem     *umem;         /**< Ponteiro para a área de memória partilhada UMEM */
    void                *buffer;       /**< Endereço base da memória virtual alocada para buffers */
    struct xsk_socket   *xsk;          /**< Instância abstrata do socket AF_XDP */
    struct bpf_object   *bpf_obj;      /**< Objeto eBPF carregado via libbpf */
    int                  ifindex;      /**< Índice numérico da interface de rede alvo */
    int                  prog_fd;      /**< File descriptor do programa XDP principal */
    int                  map_fd;       /**< File descriptor do mapa eBPF (xsks_map) */
    uint32_t             xdp_flags;    /**< Flags aplicados na vinculação XDP (DRV/Native) */
    uint64_t             tx_frame_idx; /**< Índice rotativo para o próximo frame livre do segmento de TX */
};

/**
 * @brief Inicializa e configura o ambiente eBPF / AF_XDP na interface especificada.
 * @param ifname Nome legível da interface de rede (ex: "eth0").
 * @return Ponteiro para a estrutura xsk_info alocada, ou NULL em caso de falha.
 */
struct xsk_info *init_xsk_socket(const char *ifname);

/**
 * @brief Realiza o desanexamento do programa XDP e liberta todos os recursos do socket.
 * @param xsk Ponteiro para o contexto do socket obtido em init_xsk_socket.
 * @param ifname Nome da interface de rede associada.
 */
void cleanup_xsk_socket(struct xsk_info *xsk, const char *ifname);

/**
 * @brief Envia um pacote stealth formatado através do ring de TX da interface.
 * @param xsk Ponteiro para o contexto operacional do socket.
 * @param pkt Ponteiro para a estrutura populada contendo os dados e assinaturas.
 * @return 0 em caso de sucesso, -1 se o anel de transmissão estiver cheio.
 */
int xsk_send_packet(struct xsk_info *xsk, stealth_pkt_t *pkt);

/**
 * @brief Verifica o anel de receção e extrai um frame stealth se disponível.
 * @param xsk Ponteiro para o contexto operacional do socket.
 * @param pkt Ponteiro de destino onde o conteúdo do frame será copiado.
 * @return 1 se um pacote foi recebido com sucesso, 0 se não existiam dados pendentes.
 */
int xsk_receive_packet(struct xsk_info *xsk, stealth_pkt_t *pkt);

#endif /* STEALTH_NET_H */