#!/bin/bash
set -e

## @file stealth_setup.sh
## @brief Script de automatização para isolamento e provisionamento do ambiente eBPF/XDP.
## @details Este script limpa configurações anteriores, desativa offloads de hardware (GRO/LRO),
##          força a alocação de canais combinados para a Queue 0 (exigência do AF_XDP) e isola 
##          as interfaces físicas da Mellanox ConnectX-4 em dois Network Namespaces (mac1 e mac2).
## @author Pedro Galvão
## @date 2026

NS1="mac1"  ##< Namespace do Nó 1
NS2="mac2"  ##< Namespace do Nó 2
IF1="enp2s0f0np0"  ##< Interface física alocada ao Nó 1
IF2="enp2s0f1np1"  ##< Interface física alocada ao Nó 2

echo "### Setup XDP L2 — ConnectX-4 em namespaces ###"

# Limpar estado anterior
sudo ip netns exec $NS1 ip link set $IF1 netns 1 2>/dev/null || true
sudo ip netns exec $NS2 ip link set $IF2 netns 1 2>/dev/null || true
sudo ip netns del $NS1 2>/dev/null || true
sudo ip netns del $NS2 2>/dev/null || true

# Configurar interfaces enquanto estão no host
sudo ip link set $IF1 up
sudo ip link set $IF2 up
echo "Ajustando combined 1..."
sudo ethtool -L $IF1 combined 1
sudo ethtool -L $IF2 combined 1
sudo ethtool -K $IF1 gro off lro off 2>/dev/null || true
sudo ethtool -K $IF2 gro off lro off 2>/dev/null || true
sudo ip link set dev $IF1 xdp off 2>/dev/null || true
sudo ip link set dev $IF2 xdp off 2>/dev/null || true

# Criar namespaces e mover interfaces
sudo ip netns add $NS1
sudo ip netns add $NS2
sudo ip link set $IF1 netns $NS1
sudo ip link set $IF2 netns $NS2

sudo ip netns exec $NS1 ip link set $IF1 up
sudo ip netns exec $NS2 ip link set $IF2 up

# Forçar combined 1 dentro do namespace (alguns drivers resetam ao mover)
sudo ip netns exec $NS1 ethtool -L $IF1 combined 1 2>/dev/null || true
sudo ip netns exec $NS2 ethtool -L $IF2 combined 1 2>/dev/null || true

# Montar bpffs
echo "Montando bpffs..."
sudo ip netns exec $NS1 mount -t bpf bpf /sys/fs/bpf/
sudo ip netns exec $NS2 mount -t bpf bpf /sys/fs/bpf/

MAC1=$(sudo ip netns exec $NS1 ip link show $IF1 | awk '/ether/{print $2}')
MAC2=$(sudo ip netns exec $NS2 ip link show $IF2 | awk '/ether/{print $2}')

echo ""
echo "### Setup concluído ###"
echo ""
echo "MACs:"
echo "  $NS1 / $IF1 → $MAC1"
echo "  $NS2 / $IF2 → $MAC2"
echo ""
echo "Iniciar (dois terminais):"
echo "  T1: sudo ip netns exec $NS1 ./stealth_shell_xdp $IF1 $MAC2"
echo "  T2: sudo ip netns exec $NS2 ./stealth_shell_xdp $IF2 $MAC1"
echo ""
echo "Verificar stats XDP em runtime:"
echo "  sudo ip netns exec $NS1 bpftool map dump name stats_map"
echo "  sudo ip netns exec $NS2 bpftool map dump name stats_map"