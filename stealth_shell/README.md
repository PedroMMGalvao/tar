# stealth_shell_xdp

Canal de comunicação covert in-band sobre Ethernet L2, usando **AF_XDP zero-copy**, **eBPF/XDP em modo native DRV** e cifra **AES-256-CTR + HMAC-SHA256**. Desenvolvido no âmbito da unidade curricular Advanced Network Topics (MERSI, FCUP).

---

## Índice

- [Visão geral](#visão-geral)
- [Árvore de ficheiros](#árvore-de-ficheiros)
- [O que faz cada ficheiro](#o-que-faz-cada-ficheiro)
- [Arquitetura e implementação](#arquitetura-e-implementação)
  - [Camada 1 - Frame Crafting](#camada-1--frame-crafting)
  - [Camada 2 - XDP Interception](#camada-2--xdp-interception)
  - [Camada 3 - AF_XDP Userspace Consumer](#camada-3--af_xdp-userspace-consumer)
  - [Camada Criptográfica](#camada-criptográfica)
  - [Propriedades stealth](#propriedades-stealth)
- [Dependências](#dependências)
- [Compilar](#compilar)
- [Configurar o ambiente (setup)](#configurar-o-ambiente-setup)
- [Correr](#correr)
- [Verificar stats em runtime](#verificar-stats-em-runtime)
- [Limpar](#limpar)

---

## Visão geral

O canal transmite frames Ethernet broadcast de **270 bytes** com EtherType `0x88B5` (IEEE private use, sem significado IANA). Cada frame carrega um payload de 256 bytes (`stealth_pkt_t`) com magic `"STLH"`, número de sequência, IV aleatório, ciphertext AES-256-CTR e tag HMAC-SHA256.

O programa XDP (`xdp_kern.c`), carregado em modo native DRV no driver `mlx5`, filtra os frames por EtherType, valida o magic, aplica anti-replay via `replay_map` (LRU hash), e redireciona os frames para o socket AF_XDP via `bpf_redirect_map`. Em hosts sem o handler XDP, os frames são silenciosamente descartados pelo kernel como EtherType desconhecido.

```
TX                                             RX
──────────────────────────────────────────────────────────────────────
stealth_shell.c   ← stdin                     stdout →  stealth_shell.c
stealth_crypto.c  ← AES-256-CTR + HMAC        HMAC + AES-256-CTR →  stealth_crypto.c
stealth_net.c     ← xsk_send_packet()         xsk_receive_packet() →  stealth_net.c
[UMEM TX]         ← DMA zero-copy             DMA zero-copy →  [UMEM RX]
mlx5 driver       ← AF_XDP                    AF_XDP →  mlx5 driver
                  ── 270B Ethernet L2 ──►
                     EtherType 0x88B5
                     broadcast FF:FF:FF:FF:FF:FF
                                               xdp_kern.c  (kernel, pre-stack)
                                               ├── EtherType check
                                               ├── magic "STLH" check
                                               ├── replay_map lookup
                                               └── bpf_redirect_map → AF_XDP
```

---

## Árvore de ficheiros

```
stealth_shell/
├── Makefile                  # Build system (gcc + clang-bpf)
├── stealth_setup.sh          # Setup de namespaces e interfaces
├── stealth_shell.c           # Daemon principal: I/O, poll(), TX/RX loop
├── stealth_net.c             # AF_XDP: UMEM, rings, send/receive
├── stealth_net.h             # Tipos públicos: xsk_info, stealth_pkt_t, constantes
├── stealth_crypto.c          # Cifra AES-256-CTR e HMAC-SHA256 via OpenSSL 3.x
├── stealth_crypto.h          # API pública: stealth_encrypt(), stealth_decrypt()
└── xdp/
    ├── xdp_kern.c            # Programa eBPF/XDP (kernel space)
    └── xdp_prog.o            # BPF bytecode compilado pelo Makefile (gerado)
```

---

## Funcionalidade de cada ficheiro

### `stealth_shell.c`
Ponto de entrada do daemon userspace. Responsável por:
- Ler o nome da interface (`argv[1]`) e inicializar o socket AF_XDP via `init_xsk_socket()`
- Registar handlers `SIGINT`/`SIGTERM` que fazem cleanup e detach do programa XDP
- Implementar o event loop principal com `poll()` sobre `STDIN_FILENO` e o fd do socket XDP
- **TX path:** ler linha de stdin → preencher `stealth_pkt_t` (magic, seq, payload_len) → chamar `stealth_encrypt()` → chamar `xsk_send_packet()`
- **RX path:** chamar `xsk_receive_packet()` → validar magic e payload_len → chamar `stealth_decrypt()` → imprimir plaintext
- Manter um contador de sequência monotónico por sessão (`seq_counter`)

### `stealth_net.c` + `stealth_net.h`
Gestão completa de AF_XDP e do programa BPF. Expõe três funções:

| Função | Descrição |
|---|---|
| `init_xsk_socket(ifname)` | Abre o BPF object, faz attach em DRV mode, cria UMEM (2048 × 4096B), cria socket AF_XDP com `XDP_ZEROCOPY`, regista o fd em `xsks_map[0]`, preenche o fill ring com a primeira metade dos frames |
| `xsk_send_packet(xsk, pkt)` | Aloca frame da zona TX (segunda metade do UMEM), escreve Ethernet header (MAC aleatório, dst broadcast, EtherType `0x88B5`) + `stealth_pkt_t`, submete ao TX ring, acorda o kernel com `sendto(MSG_DONTWAIT)` |
| `cleanup_xsk_socket(xsk, ifname)` | Fecha socket, UMEM, liberta buffer, faz detach do programa XDP |

Define também os tipos centrais:

```c
// Payload completo - 256 bytes fixos (verificado por _Static_assert)
typedef struct __attribute__((packed)) {
    char     magic[4];       //  0: "STLH"
    uint32_t seq;            //  4: big-endian
    uint16_t payload_len;    //  8: comprimento do plaintext (≤ 198)
    uint8_t  iv[16];         // 10: AES-CTR IV aleatório por pacote
    uint8_t  payload[198];   // 26: AES-256-CTR ciphertext
    uint8_t  hmac[32];       //224: HMAC-SHA256(iv ∥ ciphertext)
} stealth_pkt_t;             //256 bytes total
```

Wire frame: `ETH (14B)` + `stealth_pkt_t (256B)` = **270 bytes**.

### `stealth_crypto.c` + `stealth_crypto.h`
Implementação criptográfica com OpenSSL 3.x. Expõe duas funções:

| Função | Descrição |
|---|---|
| `stealth_encrypt(pt, len, iv_out, ct, hmac_out)` | Gera IV com `RAND_bytes`, cifra com `EVP_CIPHER_CTX` (AES-256-CTR, `PSK_ENC`), calcula HMAC com `EVP_MAC` (HMAC-SHA256, `PSK_MAC`) sobre `(IV ∥ CT)` |
| `stealth_decrypt(ct, len, iv, hmac, pt)` | Recomputa HMAC, compara com `CRYPTO_memcmp` (tempo constante), só decifra se HMAC válido |

Chaves pré-partilhadas hardcoded (32 bytes cada):
- `PSK_ENC` - chave de cifragem AES-256-CTR
- `PSK_MAC` - chave de autenticação HMAC-SHA256 (separada, obrigatório para provas EtM)

### `xdp/xdp_kern.c`
Programa eBPF que corre no kernel, no hook XDP do driver `mlx5`, antes de qualquer alocação `sk_buff`. Define três BPF maps:

| Map | Tipo | Entries | Função |
|---|---|---|---|
| `xsks_map` | `BPF_MAP_TYPE_XSKMAP` | 64 | Mapeamento queue→socket; usado por `bpf_redirect_map()` |
| `replay_map` | `BPF_MAP_TYPE_LRU_HASH` | 65 536 | Sequências recentes para anti-replay; LRU expira implicitamente (~18h a 1 pps) |
| `stats_map` | `BPF_MAP_TYPE_PERCPU_ARRAY` | 2 | Contadores per-CPU: `[0]` matched frames, `[1]` replay drops |

Caminho de decisão (fast path, bounded latency):
1. EtherType ≠ `0x88B5` → `XDP_PASS`
2. Frame demasiado curto → `XDP_PASS`
3. Magic ≠ `"STLH"` → `XDP_PASS`
4. Seq encontrado em `replay_map` → `XDP_DROP` + incrementa contador
5. `bpf_redirect_map(&xsks_map, 0, XDP_DROP)` → AF_XDP socket

### `stealth_setup.sh`
Script de setup do ambiente de teste num único host físico:
1. Limpar estado anterior (detach XDP, remover namespaces existentes)
2. Configurar interfaces no host: `ethtool -L combined 1` (obrigatório - RSS com múltiplas queues causa perda silenciosa, AF_XDP bind à queue 0), `GRO/LRO off`
3. Criar namespaces `mac1` e `mac2`, mover interfaces para cada um
4. Montar `bpffs` dentro de cada namespace (`mount -t bpf bpf /sys/fs/bpf/`)

### `Makefile`
Dois targets principais:

| Target | Ação |
|---|---|
| `all` | Compila `xdp/xdp_kern.c` com clang para BPF bytecode (`xdp/xdp_prog.o`), depois compila e linka `stealth_shell_xdp` com gcc |
| `clean` | Remove `.o`, `stealth_shell_xdp` e `xdp/xdp_prog.o` |

Flags relevantes:
- BPF: `-O2 -g -target bpf -D__BPF_TRACING__` - o `-g` é obrigatório para gerar BTF metadata que `libbpf` precisa de carregar
- Userspace: `-Wall -Wextra -O2 -D_GNU_SOURCE`
- Linker: `-lxdp -lbpf -lssl -lcrypto`

---

## Arquitetura e implementação

### Camada 1 - Frame Crafting

O frame de 270 bytes é construído diretamente num slot do UMEM TX, sem cópias intermédias:

```
Offset  Size  Campo
──────────────────────────────────────────────────
 0       6B   h_dest    FF:FF:FF:FF:FF:FF (broadcast)
 6       6B   h_source  MAC aleatório (/dev/urandom, bit locally-admin set)
12       2B   h_proto   0x88B5 (htons)
14       4B   magic     "STLH"
18       4B   seq       htonl(seq_counter++)
22       2B   payload_len
24      16B   iv        RAND_bytes
40     198B   payload   AES-256-CTR ciphertext
238     32B   hmac      HMAC-SHA256(iv ∥ ciphertext)
──────────────────────────────────────────────────
         270B total
```

O MAC de origem é gerado com `fread(/dev/urandom)`, com o bit locally-administered (`mac[0] |= 0x02`) e o bit multicast limpo (`mac[0] &= 0xFE`), resultando num endereço unicast válido mas diferente por frame - impede correlação de frames por análise L2.

### Camada 2 - XDP Interception

O programa BPF é carregado via `bpf_object__open` + `bpf_object__load` e anexado com `bpf_xdp_attach(..., XDP_FLAGS_DRV_MODE, NULL)`. Antes do attach, são feitos detach de todos os modos (DRV, SKB, HW) para eliminar programas residuais de sessões anteriores, seguido de `usleep(100ms)` para o kernel processar.

Após o attach, o daemon verifica que o `prog_id` do programa anexado à interface corresponde ao `prog_id` do objeto carregado - falha explicitamente se houver mismatch.

O socket AF_XDP é criado com `XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD` (não carrega um segundo programa XDP) e registado em `xsks_map[0]` via `bpf_map_update_elem`.

### Camada 3 - AF_XDP Userspace Consumer

O UMEM de `2048 × 4096 bytes` é dividido em duas zonas:

```
Frame 0..1023    → Fill ring (RX) - pré-carregados no init
Frame 1024..2047 → TX zone - tx_frame_idx incrementa ciclicamente
```

Esta divisão foi introduzida para resolver um bug crítico onde o kernel e o userspace sobrescreviam os buffers um do outro quando o UMEM era partilhado sem partição.

**RX path:**
1. `xsk_ring_cons__peek(&rx, 1, &idx)` - verifica se há frame disponível
2. Lê `addr` e `len` do descritor
3. `xsk_umem__get_data(buffer, addr)` - acesso direto ao UMEM (zero-copy)
4. `memcpy(pkt, frame + ETH_HDR_LEN, sizeof(stealth_pkt_t))`
5. Devolve frame ao fill ring para reutilização

**TX path:**
1. `xsk_ring_prod__reserve(&tx, 1, &idx)`
2. Drain do completion ring (liberta frames TX já enviados)
3. Escreve Ethernet header + `stealth_pkt_t` no slot UMEM
4. `xsk_ring_prod__submit(&tx, 1)`
5. Se `xsk_ring_prod__needs_wakeup()` → `sendto(..., MSG_DONTWAIT)`

### Camada Criptográfica

Segue o paradigma **Encrypt-then-MAC (EtM)**:

```
Plaintext
   │
   ▼
RAND_bytes(16) ──► IV
   │
   ▼
AES-256-CTR(PSK_ENC, IV) ──► Ciphertext
   │
   ▼  ┌── IV ──┐
HMAC-SHA256(PSK_MAC, IV ∥ Ciphertext) ──► Tag (32B)
```

Na decifragem, o HMAC é **sempre verificado antes** de qualquer decifragem, usando `CRYPTO_memcmp` (comparação em tempo constante - evita timing side-channels). Se o HMAC falhar, o pacote é descartado sem tentar decifrar.

A API `EVP_MAC` do OpenSSL 3.x é usada em modo incremental: `EVP_MAC_update(ctx, iv, 16)` seguido de `EVP_MAC_update(ctx, ct, len)` - evita alocar buffer para concatenar IV e CT.

Incluir o IV no scope do HMAC previne **IV-replacement attacks**: em AES-CTR, substituir o IV altera o keystream sem alterar o CT, corrompendo o plaintext de forma potencialmente controlada. Com o IV autenticado, qualquer alteração ao IV invalida o tag antes da decifragem.

### Propriedades stealth

| Método de interceção | Vê frames? | Razão |
|---|---|---|
| `tcpdump` / `AF_PACKET` no receptor | **Não** | XDP zero-copy bypassa kernel stack na receção |
| `tcpdump` / `AF_PACKET` no emissor | **Não** | AF_XDP TX bypassa kernel stack e `tc` egress hooks |
| `tc` egress mirror no emissor | **Não** | `XDP_FLAGS_DRV_MODE` e `tc clsact` conflituam no `mlx5` |
| Switch não gerido (3ª porta) | **Parcial** | Broadcast flooded - frame existe, payload encriptado |
| Switch gerido com SPAN | **Sim** | Mirror ocorre antes da NIC; EtherType e magic visíveis |
| Hardware TAP (inline) | **Sim** | Intercepção física; payload encriptado |

---

## Dependências

```bash
# Ubuntu 24.04
sudo apt install -y \
    clang llvm \
    libbpf-dev \
    libxdp-dev \
    libssl-dev \
    gcc make \
    ethtool \
    linux-tools-$(uname -r)   # bpftool
```

Hardware requerido: NIC com suporte a XDP native mode e AF_XDP zero-copy (testado em Mellanox ConnectX-4, driver `mlx5`, kernel 6.8).

---

## Compilar

```bash
make
```

Produz:
- `xdp/xdp_prog.o` - BPF bytecode com BTF metadata
- `stealth_shell_xdp` - daemon userspace

```bash
make clean   # remove todos os artefactos compilados
```

---

## Configurar o ambiente (setup)

O script configura dois namespaces Linux num único host com a ConnectX-4 dual-port:

```bash
sudo ./stealth_setup.sh
```

O script executa as seguintes etapas:
1. Remove namespaces e interfaces em estado residual
2. Coloca as interfaces no host e configura `combined 1`, `GRO off`, `LRO off`
3. Cria os namespaces `mac1` e `mac2`
4. Move `enp2s0f0np0` → `mac1` e `enp2s0f1np1` → `mac2`
5. Faz `up` às interfaces dentro de cada namespace
6. Monta `bpffs` em `/sys/fs/bpf/` dentro de cada namespace

> **Atenção:** `ethtool -L combined 1` é obrigatório antes de criar o socket AF_XDP.
> Com múltiplas queues ativas, o RSS pode distribuir frames para queues não associadas
> ao socket (bind feito à queue 0), causando perda silenciosa de pacotes.

No final, o script imprime os MACs das interfaces e os comandos para iniciar:

```
### Setup concluído ###

MACs:
  mac1 / enp2s0f0np0 → aa:bb:cc:dd:ee:ff
  mac2 / enp2s0f1np1 → 11:22:33:44:55:66

Iniciar (dois terminais):
  T1: sudo ip netns exec mac1 ./stealth_shell_xdp enp2s0f0np0
  T2: sudo ip netns exec mac2 ./stealth_shell_xdp enp2s0f1np1
```

---

## Correr

Abrir dois terminais após o setup:

**Terminal 1 (namespace mac1):**
```bash
sudo ip netns exec mac1 ./stealth_shell_xdp enp2s0f0np0
```

**Terminal 2 (namespace mac2):**
```bash
sudo ip netns exec mac2 ./stealth_shell_xdp enp2s0f1np1
```

O daemon imprime ao arranque:

```
[+] XDP NATIVE em 'enp2s0f0np0' - prog_id nosso=42 anexado=42 ✓
[+] AF_XDP socket: NATIVE + ZERO-COPY on 'enp2s0f0np0'
[+] Socket fd=7 registado em xsks_map[0]
[+] UMEM: 1024 frames RX | 1024 frames TX

>>> Stealth Shell L2 activo em enp2s0f0np0 <<<

MAC local  :  aa bb cc dd ee ff
MAC remoto :  ff ff ff ff ff ff
EtherType  : 0x88B5
Crypto     : AES-256-CTR + HMAC-SHA256
Frame      : 270 bytes (Eth + stealth_pkt_t)
XDP mode   : NATIVE (DRV) + ZERO-COPY
```

Escrever uma mensagem em qualquer terminal e premir Enter para enviar. A outra ponta recebe, verifica o HMAC e decifra automaticamente.

Para sair: `Ctrl+C` (faz cleanup e detach do programa XDP).

---

## Verificar stats em runtime

Enquanto o daemon está a correr, é possível inspecionar os contadores BPF:

```bash
# Frames matched (EtherType + magic + anti-replay passaram)
sudo ip netns exec mac1 bpftool map dump name stats_map

# Dump completo do replay_map (sequências registadas)
sudo ip netns exec mac1 bpftool map dump name replay_map

# Ver o programa XDP carregado
sudo ip netns exec mac1 bpftool prog show
```

---

## Limpar

```bash
# Remover namespaces e devolver interfaces ao host
sudo ip netns exec mac1 ip link set enp2s0f0np0 netns 1
sudo ip netns exec mac2 ip link set enp2s0f1np1 netns 1
sudo ip netns del mac1
sudo ip netns del mac2

# Remover artefactos de compilação
make clean
```

Ou simplesmente correr `stealth_unsetup.sh` novamente - a primeira coisa que faz é limpar o estado anterior.
