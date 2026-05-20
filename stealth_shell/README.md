# stealth_shell_xdp

Este trabalho implementa um canal de comunicação encoberto, in-band, sobre Ethernet L2, usando **AF_XDP zero-copy** e **eBPF/XDP em modo native DRV**. Ao nível da segurança, é aplicada a cifra **AES-256-CTR com HMAC-SHA256**.
Desenvolvido no âmbito da unidade curricular Advanced Network Topics (MERSI, FCUP).

---

## Índice

- [Visão geral](#visão-geral)
- [Árvore de ficheiros](#árvore-de-ficheiros)
- [O que faz cada ficheiro](#o-que-faz-cada-ficheiro)
- [Arquitetura e implementação](#arquitetura-e-implementação)
  - [Camada 1 - Construção da trama](#camada-1--construção-da-trama)
  - [Camada 2 - Interceção XDP](#camada-2--interceção-xdp)
  - [Camada 3 - Consumidor AF_XDP em espaço de utilizador](#camada-3--consumidor-af_xdp-em-espaço-de-utilizador)
  - [Camada Criptográfica](#camada-criptográfica)
  - [Propriedades stealth](#propriedades-stealth)
- [Dependências](#dependências)
- [Compilar](#compilar)
- [Gerar documentação](#gerar-documentação)
- [Configurar o ambiente (setup)](#configurar-o-ambiente-setup)
- [Correr](#correr)
- [Verificar estatísticas em execução](#verificar-estatísticas-em-execução)
- [Limpar](#limpar)

---

## Visão geral

O canal transmite tramas Ethernet em broadcast de **270 bytes** com EtherType `0x88B5` (IEEE private use, sem significado IANA). Assim, cada trama transporta um payload de 256 bytes (`stealth_pkt_t`) com magic `"STLH"`, número de sequência, IV aleatório, texto cifrado AES-256-CTR e tag HMAC-SHA256.

O programa XDP (`xdp_kern.c`), carregado em modo native DRV no driver `mlx5`, permite:
- filtragem das tramas por EtherType;
- validação do magic;
- aplicação de anti-replay via `replay_map` (LRU hash);
- redirecionamento das tramas para o socket AF_XDP via `bpf_redirect_map`.

Nos hosts sem o programa XDP correspondente, as tramas são descartadas silenciosamente pelo kernel por terem um EtherType desconhecido.

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
├── Makefile                  # Sistema de compilação (gcc + clang-bpf)
├── stealth_setup.sh          # Configuração de namespaces e interfaces
├── stealth_unsetup.sh        # Limpeza dos namespaces e reposição das interfaces
├── stealth_shell.c           # Daemon principal: I/O, poll(), ciclo TX/RX
├── stealth_net.c             # AF_XDP: UMEM, rings, send/receive
├── stealth_net.h             # Tipos públicos: xsk_info, stealth_pkt_t, constantes
├── stealth_crypto.c          # Cifra AES-256-CTR e HMAC-SHA256 via OpenSSL 3.x
├── stealth_crypto.h          # API pública: stealth_encrypt(), stealth_decrypt()
├── Doxyfile                  # Configuração do Doxygen para gerar documentação
├── doc/                      # Documentação gerada pelo Doxygen (HTML/LaTeX)
└── xdp/
    ├── xdp_kern.c            # Programa eBPF/XDP (espaço de kernel)
    └── xdp_prog.o            # BPF bytecode compilado pelo Makefile (gerado)
```

---

## Funcionalidade de cada ficheiro

### `stealth_shell.c`
Este é o ponto de entrada do daemon em espaço de utilizador, sendo responsável por:
- ler o nome da interface (`argv[1]`) e inicializar o socket AF_XDP via `init_xsk_socket()`;
- registar gestores de sinal `SIGINT`/`SIGTERM`, que fazem a limpeza e removem o programa XDP;
- implementar o ciclo principal com `poll()` sobre `STDIN_FILENO` e o fd do socket XDP;
- **caminho TX:** ler uma linha de `stdin` → preencher `stealth_pkt_t` (magic, seq, payload_len) → chamar `stealth_encrypt()` → chamar `xsk_send_packet()`;
- **caminho RX:** chamar `xsk_receive_packet()` → validar magic e payload_len → chamar `stealth_decrypt()` → imprimir o texto limpo;
- manter um contador de sequência monotónico por sessão (`seq_counter`);
- mostrar informação de debug em execução: mensagem, sequência, IV, texto cifrado e HMAC.

> Nota: apesar de a mensagem de `Usage` ainda apresentar `<dst_mac>`, o código atual só usa `argv[1]`. O destino usado em `xsk_send_packet()` é broadcast (`FF:FF:FF:FF:FF:FF`).

### `stealth_net.c` + `stealth_net.h`
Gestão completa de AF_XDP e do programa BPF. Expõe três funções:

| Função | Descrição |
|---|---|
| `init_xsk_socket(ifname)` | Abre o objeto BPF, anexa-o em modo DRV, cria o UMEM (2048 × 4096B), cria o socket AF_XDP com `XDP_ZEROCOPY`, regista o fd em `xsks_map[0]` e preenche o fill ring com a primeira metade dos buffers |
| `xsk_send_packet(xsk, pkt)` | Aloca uma frame da zona TX (segunda metade do UMEM), escreve o cabeçalho Ethernet (MAC aleatório, destino broadcast, EtherType `0x88B5`) + `stealth_pkt_t`, submete ao TX ring e acorda o kernel com `sendto(MSG_DONTWAIT)` |
| `xsk_receive_packet(xsk, pkt)` | Lê um descritor do RX ring, copia o `stealth_pkt_t` depois do cabeçalho Ethernet e devolve o buffer ao fill ring |
| `cleanup_xsk_socket(xsk, ifname)` | Fecha o socket e o UMEM, liberta o buffer e remove o programa XDP da interface |

Define também os tipos centrais:

```c
// Payload completo - 256 bytes fixos (verificado por _Static_assert)
typedef struct __attribute__((packed)) {
    char     magic[4];       //  0: "STLH"
    uint32_t seq;            //  4: big-endian
    uint16_t payload_len;    //  8: comprimento do texto limpo (≤ 198)
    uint8_t  iv[16];         // 10: AES-CTR IV aleatório por pacote
    uint8_t  payload[198];   // 26: texto cifrado AES-256-CTR
    uint8_t  hmac[32];       //224: HMAC-SHA256(iv ∥ texto cifrado)
} stealth_pkt_t;             //256 bytes total
```

Trama no fio: `ETH (14B)` + `stealth_pkt_t (256B)` = **270 bytes**.

### `stealth_crypto.c` + `stealth_crypto.h`
Implementação criptográfica com OpenSSL 3.x. Expõe duas funções:

| Função | Descrição |
|---|---|
| `stealth_encrypt(pt, len, iv_out, ct, hmac_out)` | Gera o IV com `RAND_bytes`, cifra com `EVP_CIPHER_CTX` (AES-256-CTR, `PSK_ENC`) e calcula o HMAC com `EVP_MAC` (HMAC-SHA256, `PSK_MAC`) sobre `(IV ∥ CT)` |
| `stealth_decrypt(ct, len, iv, hmac, pt)` | Recalcula o HMAC, compara-o com `CRYPTO_memcmp` (tempo constante) e só decifra se o HMAC for válido |

Chaves pré-partilhadas embutidas no código (32 bytes cada):
- `PSK_ENC` - chave de cifragem AES-256-CTR;
- `PSK_MAC` - chave de autenticação HMAC-SHA256 (separada, obrigatório para provas EtM).

### `xdp/xdp_kern.c`
Programa eBPF que corre no kernel, no hook XDP do driver `mlx5`, antes de qualquer alocação `sk_buff`. Define três BPF maps:

| Map | Tipo | Entries | Função |
|---|---|---|---|
| `xsks_map` | `BPF_MAP_TYPE_XSKMAP` | 64 | Mapeamento queue→socket; usado por `bpf_redirect_map()` |
| `replay_map` | `BPF_MAP_TYPE_LRU_HASH` | 65 536 | Sequências recentes para anti-replay; LRU expira implicitamente (~18h a 1 pps) |
| `stats_map` | `BPF_MAP_TYPE_PERCPU_ARRAY` | 2 | Contadores per-CPU: `[0]` tramas aceites, `[1]` drops por replay |

Caminho de decisão (fast path, bounded latency):
1. EtherType ≠ `0x88B5` → `XDP_PASS`;
2. frame demasiado curto → `XDP_PASS`;
3. magic ≠ `"STLH"` → `XDP_PASS`;
4. seq encontrado em `replay_map` → `XDP_DROP` + incremento do contador;
5. `bpf_redirect_map(&xsks_map, 0, XDP_DROP)` → socket AF_XDP.

### `stealth_setup.sh`
Script de setup do ambiente de teste num único host físico:
1. limpar o estado anterior (remoção do programa XDP e dos namespaces existentes);
2. configurar as interfaces no host: `ethtool -L combined 1` (obrigatório, porque RSS com múltiplas queues causa perda silenciosa, dado que o AF_XDP faz bind à queue 0) e `GRO/LRO off`;
3. criar os namespaces `mac1` e `mac2` e mover uma interface para cada um;
4. montar `bpffs` dentro de cada namespace (`mount -t bpf bpf /sys/fs/bpf/`).

### `stealth_unsetup.sh`
Script de limpeza do cenário de teste. Devolve as interfaces `enp2s0f0np0` e `enp2s0f1np1` ao namespace principal (`netns 1`) e remove os namespaces `mac1` e `mac2`.

### `Makefile`
Dois targets principais:

| Target | Ação |
|---|---|
| `all` | Compila `xdp/xdp_kern.c` com clang para BPF bytecode (`xdp/xdp_prog.o`) e depois compila e faz a ligação de `stealth_shell_xdp` com gcc |
| `clean` | Remove `.o`, `stealth_shell_xdp` e `xdp/xdp_prog.o` |

Flags relevantes:
- BPF: `-O2 -g -target bpf -D__BPF_TRACING__` - o `-g` é obrigatório para gerar os metadados BTF que a `libbpf` precisa de carregar;
- espaço de utilizador: `-Wall -Wextra -O2 -D_GNU_SOURCE`;
- linker: `-lxdp -lbpf -lssl -lcrypto`.

### `Doxyfile` + `doc/`
Configuração do Doxygen para gerar documentação automática do projeto a partir dos comentários `/** ... */` nos ficheiros C, headers e scripts.

Opções relevantes confirmadas no `Doxyfile`:
- `PROJECT_NAME = "XDP Stealth Shell"`;
- `OUTPUT_DIRECTORY = "doc"`;
- `INPUT = .` e `RECURSIVE = YES`, ou seja, a documentação é gerada a partir da pasta do projeto, incluindo subpastas como `xdp/`;
- `GENERATE_HTML = YES` e `GENERATE_LATEX = YES`;
- `HAVE_DOT = YES`, `CALL_GRAPH = YES` e `CALLER_GRAPH = YES`, para gerar grafos de chamadas quando o Graphviz/Dot estiver disponível.

A pasta `doc/` contém os artefactos gerados, nomeadamente `doc/html/index.html` para navegação no browser e ficheiros LaTeX em `doc/latex/`.

---

## Arquitetura e implementação

### Camada 1 - Construção da trama

A trama de 270 bytes é construída diretamente num slot do UMEM TX, sem cópias intermédias:

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
40     198B   payload   texto cifrado AES-256-CTR
238     32B   hmac      HMAC-SHA256(iv ∥ texto cifrado)
──────────────────────────────────────────────────
         270B total
```

O MAC de origem é gerado com `fread(/dev/urandom)`, com o bit locally-administered (`mac[0] |= 0x02`) ativo e o bit multicast limpo (`mac[0] &= 0xFE`). O resultado é um endereço unicast válido, mas diferente em cada trama, o que dificulta a correlação por análise L2.

### Camada 2 - Interceção XDP

O programa BPF é carregado via `bpf_object__open` + `bpf_object__load` e anexado com `bpf_xdp_attach(..., XDP_FLAGS_DRV_MODE, NULL)`. Antes da anexação, é feita a remoção em todos os modos (DRV, SKB, HW) para eliminar programas residuais de sessões anteriores, seguida de `usleep(100ms)` para dar tempo ao kernel de processar a alteração.

Após a anexação, o daemon verifica se o `prog_id` do programa anexado à interface corresponde ao `prog_id` do objeto carregado. Se houver uma diferença entre ambos, a execução falha explicitamente.

O socket AF_XDP é criado com `XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD` (não carrega um segundo programa XDP) e registado em `xsks_map[0]` via `bpf_map_update_elem`.

### Camada 3 - Consumidor AF_XDP em espaço de utilizador

O UMEM de `2048 × 4096 bytes` é dividido em duas zonas:

```
Slots 0..1023    → Fill ring (RX) - pré-carregados na inicialização
Slots 1024..2047 → Zona TX - tx_frame_idx incrementa ciclicamente
```

Esta divisão foi introduzida para resolver um bug crítico em que o kernel e o espaço de utilizador sobrescreviam os buffers um do outro quando o UMEM era partilhado sem partição.

**Caminho RX:**
1. `xsk_ring_cons__peek(&rx, 1, &idx)` - verifica se há uma frame disponível;
2. lê `addr` e `len` do descritor;
3. `xsk_umem__get_data(buffer, addr)` - acesso direto ao UMEM (zero-copy);
4. `memcpy(pkt, frame + ETH_HDR_LEN, sizeof(stealth_pkt_t))`;
5. devolve a frame ao fill ring para reutilização.

**Caminho TX:**
1. `xsk_ring_prod__reserve(&tx, 1, &idx)`;
2. drain do completion ring (liberta tramas TX já enviadas);
3. escreve o cabeçalho Ethernet + `stealth_pkt_t` no slot UMEM;
4. `xsk_ring_prod__submit(&tx, 1)`;
5. se `xsk_ring_prod__needs_wakeup()` → `sendto(..., MSG_DONTWAIT)`.

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

Na decifragem, o HMAC é **sempre verificado antes** de qualquer operação de decifragem, usando `CRYPTO_memcmp` (comparação em tempo constante, evitando timing side-channels). Se o HMAC falhar, o pacote é descartado sem tentar decifrar.

A API `EVP_MAC` do OpenSSL 3.x é usada em modo incremental: `EVP_MAC_update(ctx, iv, 16)` seguido de `EVP_MAC_update(ctx, ct, len)`. Assim, evita-se alocar um buffer apenas para concatenar IV e CT.

Incluir o IV no âmbito do HMAC previne **IV-replacement attacks**: em AES-CTR, substituir o IV altera o keystream sem alterar o CT, corrompendo o texto limpo de forma potencialmente controlada. Com o IV autenticado, qualquer alteração ao IV invalida a tag antes da decifragem.

### Propriedades stealth

| Método de interceção | Vê tramas? | Razão |
|---|---|---|
| `tcpdump` / `AF_PACKET` no recetor | **Não** | XDP zero-copy contorna a stack do kernel na receção |
| `tcpdump` / `AF_PACKET` no emissor | **Não** | AF_XDP TX contorna a stack do kernel e os hooks `tc` egress |
| `tc` egress mirror no emissor | **Não** | `XDP_FLAGS_DRV_MODE` e `tc clsact` conflituam no `mlx5` |
| Switch não gerido (3.ª porta) | **Parcial** | Broadcast propagado - a trama existe, mas o payload está cifrado |
| Switch gerido com SPAN | **Sim** | Mirror ocorre antes da NIC; EtherType e magic visíveis |
| Hardware TAP (inline) | **Sim** | Interceção física; payload cifrado |

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
    doxygen graphviz \
    linux-tools-$(uname -r)   # bpftool
```

Hardware requerido: NIC com suporte a XDP native mode e AF_XDP zero-copy (testado em Mellanox ConnectX-4, driver `mlx5`, kernel 6.8).

---

## Compilar

```bash
make
```

Produz:
- `xdp/xdp_prog.o` - BPF bytecode com metadados BTF;
- `stealth_shell_xdp` - daemon em espaço de utilizador.

```bash
make clean   # remove todos os artefactos compilados
```

---

## Gerar documentação

O projeto inclui um `Doxyfile`, por isso a documentação pode ser gerada novamente com:

```bash
cd stealth_shell
doxygen Doxyfile
```

O resultado é escrito em `doc/`. A página principal HTML fica em:

```bash
doc/html/index.html
```

O Doxygen lê os comentários dos ficheiros `.c`, `.h` e scripts, e também gera grafos de chamadas/callers quando o `graphviz` está instalado.

---

## Configurar o ambiente (setup)

O script configura dois namespaces Linux num único host com uma ConnectX-4 dual-port:

```bash
sudo ./stealth_setup.sh
```

O script executa as seguintes etapas:
1. remove namespaces e interfaces em estado residual;
2. coloca as interfaces no host e configura `combined 1`, `GRO off` e `LRO off`;
3. cria os namespaces `mac1` e `mac2`;
4. move `enp2s0f0np0` → `mac1` e `enp2s0f1np1` → `mac2`;
5. coloca as interfaces em estado `up` dentro de cada namespace;
6. monta `bpffs` em `/sys/fs/bpf/` dentro de cada namespace.

> **Atenção:** `ethtool -L combined 1` é obrigatório antes de criar o socket AF_XDP.
> Com múltiplas queues ativas, o RSS pode distribuir tramas para queues não associadas
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

É necessário abrir dois terminais após o setup:

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

De seguida, escreve uma mensagem em qualquer um dos terminais e prime Enter para enviar. A outra ponta recebe, verifica o HMAC e decifra automaticamente.

Para sair: `Ctrl+C` (faz a limpeza e remove o programa XDP da interface).

---

## Verificar estatísticas em execução

Enquanto o daemon está a correr, é possível inspecionar os contadores BPF:


```bash
# Frames matched (EtherType + magic + anti-replay passaram)
sudo ip netns exec mac1 bpftool map dump name stats_map

# Dump completo do replay_map (sequências registadas)
sudo ip netns exec mac1 bpftool map dump name replay_map

# Ver o programa XDP carregado
sudo ip netns exec mac1 bpftool prog show

#Ver o trace_pipe do kernel
sudo cat /sys/kernel/debug/tracing/trace_pipe

#Ver que não esta no tcpdup
sudo ip netns exec mac2 tcpdump -i enp2s0f1np1 -e -n -xx
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

Também pode correr `stealth_unsetup.sh`; a sua função é limpar o cenário anterior e devolver as interfaces ao namespace principal.
