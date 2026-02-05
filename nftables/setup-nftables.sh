#!/bin/bash
# =============================================================================
# VortexL2 nftables Setup Script
# =============================================================================
# Configures kernel-level port forwarding using nftables DNAT/masquerade
# Supports both TCP and UDP with stateful connection tracking
# =============================================================================

set -euo pipefail

# ---- CONFIGURATION ----
# Modify these values according to your setup
PORT_RANGE="${PORT_RANGE:-10000-60000}"    # Port range to forward
DEST_IP="${DEST_IP:-}"                      # Destination IP (required)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- COLORS ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# ---- FUNCTIONS ----

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_nftables() {
    if ! command -v nft &> /dev/null; then
        log_error "nftables is not installed"
        log_info "Install with: apt install nftables"
        exit 1
    fi
}

enable_ip_forward() {
    log_info "Enabling IP forwarding..."
    
    # Enable immediately
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Make persistent
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    
    # Also set via sysctl.d for systemd systems
    cat > /etc/sysctl.d/99-vortexl2-forward.conf << EOF
# VortexL2 - Enable IP forwarding for NAT
net.ipv4.ip_forward=1
net.netfilter.nf_conntrack_max=262144
net.netfilter.nf_conntrack_tcp_timeout_established=86400
EOF
    
    sysctl -p /etc/sysctl.d/99-vortexl2-forward.conf &>/dev/null || true
    log_success "IP forwarding enabled"
}

generate_config() {
    local dest_ip="$1"
    local port_range="$2"
    local output_file="$3"
    
    log_info "Generating nftables config..."
    log_info "  Destination IP: ${dest_ip}"
    log_info "  Port range: ${port_range}"
    
    cat > "$output_file" << EOF
#!/usr/sbin/nft -f
# =============================================================================
# VortexL2 - Kernel-Level TCP+UDP Port Forwarding
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Destination: ${dest_ip} | Ports: ${port_range}
# =============================================================================

# Flush existing VortexL2 tables
table inet vortexl2_filter
delete table inet vortexl2_filter

table ip vortexl2_nat
delete table ip vortexl2_nat


# =============================================================================
# FILTER TABLE - Stateful Firewall (drop by default)
# =============================================================================
table inet vortexl2_filter {
    
    chain forward {
        type filter hook forward priority 0; policy drop;
        
        # Stateful connection tracking
        ct state established,related accept
        ct state invalid drop
        
        # Allow forwarded traffic in port range
        tcp dport ${port_range} accept
        udp dport ${port_range} accept
        
        # ICMP for path MTU discovery
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
    }
    
    chain input {
        type filter hook input priority 0; policy accept;
        
        ct state established,related accept
        ct state invalid drop
        
        tcp dport ${port_range} accept
        udp dport ${port_range} accept
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}


# =============================================================================
# NAT TABLE - DNAT + Masquerade
# =============================================================================
table ip vortexl2_nat {
    
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        
        # DNAT: Forward ports to destination
        tcp dport ${port_range} dnat to ${dest_ip}
        udp dport ${port_range} dnat to ${dest_ip}
    }
    
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        
        # Masquerade for return path
        oifname != "lo" masquerade
    }
}
EOF

    log_success "Config generated: ${output_file}"
}

apply_config() {
    local config_file="$1"
    
    log_info "Applying nftables configuration..."
    
    # Validate first
    if ! nft -c -f "$config_file" 2>/dev/null; then
        log_error "Configuration validation failed!"
        nft -c -f "$config_file"
        exit 1
    fi
    
    # Apply
    nft -f "$config_file"
    log_success "nftables rules applied"
    
    # Show summary
    echo ""
    log_info "Active VortexL2 tables:"
    nft list tables | grep vortexl2 || true
}

install_persistent() {
    local config_file="$1"
    
    log_info "Installing persistent configuration..."
    
    # Copy to /etc/nftables.d/ if directory exists, otherwise use includes
    if [[ -d /etc/nftables.d ]]; then
        cp "$config_file" /etc/nftables.d/vortexl2-forward.nft
        log_success "Installed to /etc/nftables.d/vortexl2-forward.nft"
    else
        mkdir -p /etc/nftables.d
        cp "$config_file" /etc/nftables.d/vortexl2-forward.nft
        
        # Add include to main nftables.conf if not present
        if [[ -f /etc/nftables.conf ]]; then
            if ! grep -q 'include "/etc/nftables.d/vortexl2-forward.nft"' /etc/nftables.conf; then
                echo 'include "/etc/nftables.d/vortexl2-forward.nft"' >> /etc/nftables.conf
                log_success "Added include to /etc/nftables.conf"
            fi
        fi
    fi
    
    # Enable nftables service
    if systemctl is-enabled nftables &>/dev/null || systemctl enable nftables &>/dev/null; then
        log_success "nftables service enabled"
    fi
}

show_status() {
    echo ""
    echo "========================================"
    echo "VortexL2 nftables Status"
    echo "========================================"
    echo ""
    
    echo "--- Filter Rules ---"
    nft list table inet vortexl2_filter 2>/dev/null || echo "Not loaded"
    echo ""
    
    echo "--- NAT Rules ---"
    nft list table ip vortexl2_nat 2>/dev/null || echo "Not loaded"
    echo ""
    
    echo "--- Connection Tracking Stats ---"
    if [[ -f /proc/sys/net/netfilter/nf_conntrack_count ]]; then
        echo "Active connections: $(cat /proc/sys/net/netfilter/nf_conntrack_count)"
        echo "Max connections: $(cat /proc/sys/net/netfilter/nf_conntrack_max)"
    fi
}

uninstall() {
    log_info "Removing VortexL2 nftables rules..."
    
    nft delete table inet vortexl2_filter 2>/dev/null || true
    nft delete table ip vortexl2_nat 2>/dev/null || true
    
    rm -f /etc/nftables.d/vortexl2-forward.nft 2>/dev/null || true
    rm -f /etc/sysctl.d/99-vortexl2-forward.conf 2>/dev/null || true
    
    log_success "VortexL2 nftables rules removed"
}

usage() {
    cat << EOF
VortexL2 nftables Setup

Usage: $0 <command> [options]

Commands:
    install <dest_ip> [port_range]   Generate, apply, and persist nftables rules
    apply <dest_ip> [port_range]     Generate and apply rules (not persistent)
    status                           Show current nftables status
    uninstall                        Remove all VortexL2 nftables rules

Options:
    dest_ip      Destination IP for forwarded traffic (required for install/apply)
    port_range   Port range to forward (default: 10000-60000)

Examples:
    $0 install 192.168.1.100 10000-60000
    $0 apply 10.0.0.2
    $0 status
    $0 uninstall

Environment Variables:
    DEST_IP      Default destination IP
    PORT_RANGE   Default port range (default: 10000-60000)
EOF
}


# ---- MAIN ----

main() {
    local cmd="${1:-}"
    
    case "$cmd" in
        install)
            check_root
            check_nftables
            
            local dest="${2:-$DEST_IP}"
            local range="${3:-$PORT_RANGE}"
            
            if [[ -z "$dest" ]]; then
                log_error "Destination IP required"
                usage
                exit 1
            fi
            
            enable_ip_forward
            generate_config "$dest" "$range" "/tmp/vortexl2-forward.nft"
            apply_config "/tmp/vortexl2-forward.nft"
            install_persistent "/tmp/vortexl2-forward.nft"
            rm -f /tmp/vortexl2-forward.nft
            
            echo ""
            log_success "VortexL2 nftables installed and persistent!"
            log_info "Rules will be automatically restored on reboot"
            ;;
            
        apply)
            check_root
            check_nftables
            
            local dest="${2:-$DEST_IP}"
            local range="${3:-$PORT_RANGE}"
            
            if [[ -z "$dest" ]]; then
                log_error "Destination IP required"
                usage
                exit 1
            fi
            
            enable_ip_forward
            generate_config "$dest" "$range" "/tmp/vortexl2-forward.nft"
            apply_config "/tmp/vortexl2-forward.nft"
            rm -f /tmp/vortexl2-forward.nft
            
            log_warn "Rules are NOT persistent - use 'install' for persistence"
            ;;
            
        status)
            show_status
            ;;
            
        uninstall)
            check_root
            uninstall
            ;;
            
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
