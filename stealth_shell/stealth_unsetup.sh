#!/bin/bash
set -e

## @file stealth_unsetup.sh
## @brief Script de desfazimento (cleanup) do cenário de testes em rede.
## @details Devolve as interfaces de rede ConnectX-4 ao namespace padrão da máquina (Host PID 1)
##          e elimina os namespaces mac1 e mac2, restaurando o estado original da pilha de rede.
## @author Pedro Galvão
## @date 2026

NS1="mac1"
NS2="mac2"
IF1="enp2s0f0np0"
IF2="enp2s0f1np1"

echo "### Remove Setup XDP L2 — ConnectX-4 em namespaces ###"

sudo ip netns exec $NS1 ip link set $IF1 netns 1
sudo ip netns exec $NS2 ip link set $IF2 netns 1
sudo ip netns del $NS1
sudo ip netns del $NS2