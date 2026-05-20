/**
 * @file stealth_shell.c
 * @brief Programa principal (Userspace CLI) do Stealth Shell baseado em AF_XDP.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "stealth_net.h"
#include "stealth_crypto.h"

#define RST  "\x1b[0m"
#define BOLD "\x1b[1m"
#define RED  "\x1b[31m"
#define GRN  "\x1b[32m"
#define BLU  "\x1b[34m"
#define MAG  "\x1b[35m"
#define CYN  "\x1b[36m"
#define WHT  "\x1b[37m"

static struct xsk_info *g_xsk   = NULL; /**< Contexto global do socket AF_XDP */
static const char      *g_iface = NULL; /**< Guardião global do nome da interface de rede em uso */

/**
 * @brief Manipulador de sinais do sistema (SIGINT, SIGTERM) para encerramento limpo.
 * @param sig Número identificador do sinal intercetado.
 */
static void on_sigint(int sig)
{
    (void)sig;
    printf(RST "\n[*] A desligar, removendo programa XDP...\n");
    cleanup_xsk_socket(g_xsk, g_iface);
    exit(0);
}

/**
 * @brief Utilitário auxiliar para despejo hexadecimal de dados na consola (Hexdump).
 * @param label Título identificador a imprimir antes do dump.
 * @param data Ponteiro para a sequência de bytes.
 * @param len Número de bytes a processar para impressão.
 */
static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf(BOLD CYN "%s:" RST, label);
    for (size_t i = 0; i < len; i++)
        printf(" " WHT "%02X" RST, data[i]);
    printf("\n");
}

/**
 * @brief Obtém o endereço MAC de hardware associado à interface local configurada.
 * @param ifname String representativa do nome do interface de rede.
 * @param mac Array de destino com capacidade de 6 bytes.
 * @return 0 se lido com sucesso, -1 caso ocorra falha na execução do ioctl.
 */
static int get_local_mac(const char *ifname, uint8_t *mac)
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

/**
 * @brief Ponto de entrada do executável da aplicação.
 * @param argc Contador de argumentos em linha de comandos.
 * @param argv Vetor de apontadores contendo os argumentos textuais.
 * @return Código de execução (0 para término regular, 1 para falhas estruturais).
 */
int main(int argc, char **argv)
{
    if (argc < 2) {
        printf(WHT "Usage: sudo %s <interface> <dst_mac>\n" RST, argv[0]);
        printf(WHT "  e.g. sudo %s enp2s0f0np0 98:03:9b:6b:a3:03\n\n" RST, argv[0]);
        return 1;
    }

    g_iface = argv[1];

    uint8_t l_mac[6];
    uint8_t r_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    if (get_local_mac(argv[1], l_mac) < 0) {
        fprintf(stderr, "[!] Não foi possível ler MAC de '%s'\n", argv[1]);
        return 1;
    }

    g_xsk = init_xsk_socket(argv[1]);
    if (!g_xsk) {
        fprintf(stderr, "[!] AF_XDP init falhou\n");
        return 1;
    }

    signal(SIGINT,  on_sigint);
    signal(SIGTERM, on_sigint);

    printf(BOLD GRN "\n>>> Stealth Shell L2 activo em %s <<<\n\n" RST, argv[1]);
    print_hex("MAC local  ", l_mac, 6);
    print_hex("MAC remoto ", r_mac, 6);
    printf(BLU "EtherType  : 0x%04X\n" RST, STEALTH_ETHERTYPE);
    printf(BLU "Crypto     : AES-256-CTR + HMAC-SHA256\n" RST);
    printf(BLU "Frame      : %zu bytes (Eth + stealth_pkt_t)\n" RST,
           (size_t)ETH_HDR_LEN + sizeof(stealth_pkt_t));
    printf(BLU "XDP mode   : NATIVE (DRV) + ZERO-COPY\n\n" RST);

    uint32_t seq_counter = 1;

    struct pollfd fds[2] = {
        { .fd = STDIN_FILENO,                .events = POLLIN },
        { .fd = xsk_socket__fd(g_xsk->xsk), .events = POLLIN },
    };

    while (1) {
        poll(fds, 2, -1);

        if (fds[0].revents & POLLIN) {
            char buf[MAX_PAYLOAD];
            memset(buf, 0, sizeof(buf));
            if (!fgets(buf, MAX_PAYLOAD - 1, stdin)) continue;

            uint16_t msg_len = (uint16_t)strlen(buf);
            if (msg_len == 0) continue;

            stealth_pkt_t pkt;
            memset(&pkt, 0, sizeof(pkt));
            memcpy(pkt.magic,   STEALTH_MAGIC, 4);
            pkt.seq         = htonl(seq_counter++);
            pkt.payload_len = msg_len;

            if (!stealth_encrypt((uint8_t *)buf, msg_len,
                                 pkt.iv, pkt.payload, pkt.hmac)) {
                fprintf(stderr, "[!] Encriptação falhou\n");
                continue;
            }

            printf(BLU "\n[TX] Mensagem  : %.*s" RST, msg_len, buf);
            printf(MAG "[TX] Seq       : %u\n" RST, seq_counter - 1);
            print_hex("[TX] IV        ", pkt.iv,      CRYPTO_IV_SIZE);
            print_hex("[TX] Encriptado", pkt.payload, msg_len);
            print_hex("[TX] HMAC      ", pkt.hmac,    CRYPTO_HMAC_SIZE);
            fflush(stdout);

            xsk_send_packet(g_xsk, &pkt);
        }

        if (fds[1].revents & POLLIN) {
            stealth_pkt_t r_pkt;
            uint8_t clear[MAX_PAYLOAD];
            memset(clear, 0, sizeof(clear));
            if (!xsk_receive_packet(g_xsk, &r_pkt)) continue;

            if (memcmp(r_pkt.magic, STEALTH_MAGIC, 4) != 0) continue;
            if (r_pkt.payload_len == 0 ||
                r_pkt.payload_len > MAX_PAYLOAD) continue;

            printf(GRN "\n[RX] Seq       : %u\n" RST, ntohl(r_pkt.seq));
            print_hex("[RX] IV        ", r_pkt.iv,      CRYPTO_IV_SIZE);
            print_hex("[RX] Encriptado", r_pkt.payload, r_pkt.payload_len);
            print_hex("[RX] HMAC      ", r_pkt.hmac,    CRYPTO_HMAC_SIZE);

            if (stealth_decrypt(r_pkt.payload, r_pkt.payload_len,
                                r_pkt.iv, r_pkt.hmac, clear)) {
                printf(BOLD GRN "[RX] Mensagem  : %.*s\n" RST,
                       r_pkt.payload_len, (char *)clear);
            } else {
                printf(RED "[RX] HMAC inválido — pacote descartado\n" RST);
            }
            fflush(stdout);
        }
    }

    return 0;
}