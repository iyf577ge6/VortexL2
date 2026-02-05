"""
VortexL2 Port Forward Management

Kernel-level TCP+UDP port forwarding using nftables DNAT/masquerade.
Replaces user-space proxies for high-performance, stable forwarding.
"""

from __future__ import annotations

import subprocess
import logging
import shutil
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# nftables config paths
NFTABLES_DIR = Path("/etc/nftables.d")
NFTABLES_CONFIG = NFTABLES_DIR / "vortexl2-forward.nft"
SYSCTL_CONFIG = Path("/etc/sysctl.d/99-vortexl2-forward.conf")


@dataclass
class ForwardRule:
    """Represents a port forward rule."""
    port: int
    remote_ip: str
    remote_port: int
    protocol: str = "tcp+udp"
    
    def to_dict(self) -> Dict:
        return {
            "port": self.port,
            "remote": f"{self.remote_ip}:{self.remote_port}",
            "protocol": self.protocol,
        }


class ForwardManager:
    """
    Manages kernel-level port forwarding using nftables.
    
    Uses DNAT in prerouting and masquerade in postrouting for 
    high-performance TCP+UDP forwarding without user-space proxies.
    """
    
    def __init__(self, config):
        self.config = config
        self._ensure_dirs()
    
    def _ensure_dirs(self):
        """Ensure required directories exist."""
        NFTABLES_DIR.mkdir(parents=True, exist_ok=True)
    
    def _check_nftables(self) -> bool:
        """Check if nftables is available."""
        return shutil.which("nft") is not None
    
    def _run_cmd(self, cmd: str, check: bool = True) -> Tuple[bool, str]:
        """Run a shell command."""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout + result.stderr
            if check and result.returncode != 0:
                return False, output.strip()
            return True, output.strip()
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)
    
    def _enable_ip_forward(self) -> Tuple[bool, str]:
        """Enable IP forwarding in kernel."""
        try:
            # Enable immediately
            Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
            
            # Make persistent via sysctl.d
            sysctl_content = """# VortexL2 - Kernel settings for NAT forwarding
net.ipv4.ip_forward=1
net.netfilter.nf_conntrack_max=262144
net.netfilter.nf_conntrack_tcp_timeout_established=86400
"""
            SYSCTL_CONFIG.write_text(sysctl_content)
            self._run_cmd("sysctl -p /etc/sysctl.d/99-vortexl2-forward.conf", check=False)
            
            return True, "IP forwarding enabled"
        except Exception as e:
            return False, f"Failed to enable IP forwarding: {e}"
    
    def _generate_nftables_config(self, ports: List[int], dest_ip: str) -> str:
        """Generate nftables configuration for port forwarding."""
        if not ports:
            # Empty config - just delete tables
            return """#!/usr/sbin/nft -f
# VortexL2 - No ports configured
table inet vortexl2_filter
delete table inet vortexl2_filter
table ip vortexl2_nat  
delete table ip vortexl2_nat
"""
        
        # Group consecutive ports into ranges for efficiency
        port_ranges = self._ports_to_ranges(sorted(ports))
        
        # Build port match expressions
        port_expr = ", ".join(port_ranges)
        
        config = f"""#!/usr/sbin/nft -f
# =============================================================================
# VortexL2 - Kernel-Level TCP+UDP Port Forwarding
# Destination: {dest_ip} | Ports: {port_expr}
# =============================================================================

# Flush existing VortexL2 tables
table inet vortexl2_filter
delete table inet vortexl2_filter

table ip vortexl2_nat
delete table ip vortexl2_nat


# =============================================================================
# FILTER TABLE - Stateful Firewall (drop by default in forward)
# =============================================================================
table inet vortexl2_filter {{
    
    chain forward {{
        type filter hook forward priority 0; policy drop;
        
        # Stateful connection tracking
        ct state established,related accept
        ct state invalid drop
        
        # Allow forwarded traffic on configured ports
        tcp dport {{ {port_expr} }} accept
        udp dport {{ {port_expr} }} accept
        
        # ICMP for path MTU discovery
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
    }}
    
    chain input {{
        type filter hook input priority 0; policy accept;
        
        ct state established,related accept
        ct state invalid drop
        
        tcp dport {{ {port_expr} }} accept
        udp dport {{ {port_expr} }} accept
    }}
    
    chain output {{
        type filter hook output priority 0; policy accept;
    }}
}}


# =============================================================================
# NAT TABLE - DNAT + Masquerade
# =============================================================================
table ip vortexl2_nat {{
    
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        
        # DNAT: Forward ports to destination
        tcp dport {{ {port_expr} }} dnat to {dest_ip}
        udp dport {{ {port_expr} }} dnat to {dest_ip}
    }}
    
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        
        # Masquerade for return path
        oifname != "lo" masquerade
    }}
}}
"""
        return config
    
    def _ports_to_ranges(self, ports: List[int]) -> List[str]:
        """Convert list of ports to range expressions (e.g., [80, 81, 82, 443] -> ['80-82', '443'])."""
        if not ports:
            return []
        
        ranges = []
        start = ports[0]
        end = ports[0]
        
        for port in ports[1:]:
            if port == end + 1:
                end = port
            else:
                if start == end:
                    ranges.append(str(start))
                else:
                    ranges.append(f"{start}-{end}")
                start = port
                end = port
        
        # Add last range
        if start == end:
            ranges.append(str(start))
        else:
            ranges.append(f"{start}-{end}")
        
        return ranges
    
    def apply_rules(self) -> Tuple[bool, str]:
        """Generate and apply nftables rules for current config."""
        if not self._check_nftables():
            return False, "nftables not installed. Run: apt install nftables"
        
        ports = self.config.forwarded_ports
        dest_ip = self.config.remote_forward_ip
        
        if not dest_ip:
            return False, "Remote forward IP not configured"
        
        # Enable IP forwarding first
        success, msg = self._enable_ip_forward()
        if not success:
            logger.warning(msg)
        
        # Generate config
        nft_config = self._generate_nftables_config(ports, dest_ip)
        
        # Write config file
        try:
            NFTABLES_CONFIG.write_text(nft_config)
        except Exception as e:
            return False, f"Failed to write config: {e}"
        
        # Validate config
        success, msg = self._run_cmd(f"nft -c -f {NFTABLES_CONFIG}")
        if not success:
            return False, f"Config validation failed: {msg}"
        
        # Apply config
        success, msg = self._run_cmd(f"nft -f {NFTABLES_CONFIG}")
        if not success:
            return False, f"Failed to apply rules: {msg}"
        
        # Ensure nftables service is enabled for persistence
        self._run_cmd("systemctl enable nftables", check=False)
        
        # Add include to main nftables.conf if needed
        self._ensure_include()
        
        port_count = len(ports) if ports else 0
        return True, f"nftables rules applied ({port_count} ports -> {dest_ip})"
    
    def _ensure_include(self):
        """Ensure our config is included in main nftables.conf."""
        nftables_conf = Path("/etc/nftables.conf")
        include_line = f'include "{NFTABLES_CONFIG}"'
        
        if nftables_conf.exists():
            content = nftables_conf.read_text()
            if include_line not in content:
                try:
                    with nftables_conf.open("a") as f:
                        f.write(f"\n{include_line}\n")
                except Exception:
                    pass  # Non-critical
    
    def remove_rules(self) -> Tuple[bool, str]:
        """Remove all VortexL2 nftables rules."""
        results = []
        
        # Delete tables
        self._run_cmd("nft delete table inet vortexl2_filter", check=False)
        self._run_cmd("nft delete table ip vortexl2_nat", check=False)
        results.append("nftables rules removed")
        
        # Remove config file
        if NFTABLES_CONFIG.exists():
            NFTABLES_CONFIG.unlink()
            results.append("Config file removed")
        
        return True, "; ".join(results)
    
    def create_forward(self, port: int) -> Tuple[bool, str]:
        """Add a port to forwarding config and apply."""
        if port in self.config.forwarded_ports:
            return False, f"Port {port} already configured"
        
        self.config.add_port(port)
        return self.apply_rules()
    
    def remove_forward(self, port: int) -> Tuple[bool, str]:
        """Remove a port from forwarding config and apply."""
        if port not in self.config.forwarded_ports:
            return False, f"Port {port} not found"
        
        self.config.remove_port(port)
        return self.apply_rules()
    
    def add_multiple_forwards(self, ports_str: str) -> Tuple[bool, str]:
        """Add multiple port forwards from comma-separated string."""
        results = []
        ports = [p.strip() for p in ports_str.split(',') if p.strip()]
        added = []
        
        for port_str in ports:
            try:
                port = int(port_str)
                if port not in self.config.forwarded_ports:
                    self.config.add_port(port)
                    added.append(port)
                    results.append(f"Port {port}: added")
                else:
                    results.append(f"Port {port}: already exists")
            except ValueError:
                results.append(f"Port '{port_str}': invalid")
        
        # Apply all changes at once
        if added:
            success, msg = self.apply_rules()
            if success:
                results.append(f"\nnftables: {msg}")
            else:
                results.append(f"\nnftables error: {msg}")
        
        return True, "\n".join(results)
    
    def remove_multiple_forwards(self, ports_str: str) -> Tuple[bool, str]:
        """Remove multiple port forwards from comma-separated string."""
        results = []
        ports = [p.strip() for p in ports_str.split(',') if p.strip()]
        removed = []
        
        for port_str in ports:
            try:
                port = int(port_str)
                if port in self.config.forwarded_ports:
                    self.config.remove_port(port)
                    removed.append(port)
                    results.append(f"Port {port}: removed")
                else:
                    results.append(f"Port {port}: not found")
            except ValueError:
                results.append(f"Port '{port_str}': invalid")
        
        # Apply all changes at once
        if removed:
            success, msg = self.apply_rules()
            if success:
                results.append(f"\nnftables: {msg}")
            else:
                results.append(f"\nnftables error: {msg}")
        
        return True, "\n".join(results)
    
    def list_forwards(self) -> List[Dict]:
        """List all configured port forwards with status."""
        forwards = []
        dest_ip = self.config.remote_forward_ip or "not configured"
        
        # Check if rules are actually loaded
        rules_active = self._check_rules_active()
        
        for port in self.config.forwarded_ports:
            forwards.append({
                "port": port,
                "remote": f"{dest_ip}:{port}",
                "running": rules_active,
                "active_sessions": self._get_conntrack_count(port) if rules_active else 0,
            })
        
        return forwards
    
    def _check_rules_active(self) -> bool:
        """Check if nftables rules are currently loaded."""
        success, output = self._run_cmd("nft list table ip vortexl2_nat 2>/dev/null", check=False)
        return success and "vortexl2_nat" in output
    
    def _get_conntrack_count(self, port: int) -> int:
        """Get active connection count for a port from conntrack."""
        try:
            result = subprocess.run(
                f"conntrack -L -p tcp --dport {port} 2>/dev/null | wc -l",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            tcp_count = int(result.stdout.strip()) if result.stdout.strip() else 0
            
            result = subprocess.run(
                f"conntrack -L -p udp --dport {port} 2>/dev/null | wc -l",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            udp_count = int(result.stdout.strip()) if result.stdout.strip() else 0
            
            return tcp_count + udp_count
        except Exception:
            return 0
    
    def get_status(self) -> Dict:
        """Get overall forwarding status."""
        rules_active = self._check_rules_active()
        
        # Get conntrack stats
        try:
            count = Path("/proc/sys/net/netfilter/nf_conntrack_count").read_text().strip()
            max_conn = Path("/proc/sys/net/netfilter/nf_conntrack_max").read_text().strip()
            conntrack = f"{count}/{max_conn}"
        except Exception:
            conntrack = "N/A"
        
        return {
            "rules_active": rules_active,
            "port_count": len(self.config.forwarded_ports),
            "destination": self.config.remote_forward_ip,
            "conntrack": conntrack,
        }
    
    # Compatibility methods for existing code
    async def start_all_forwards(self) -> Tuple[bool, str]:
        """Apply nftables rules (async wrapper for compatibility)."""
        return self.apply_rules()
    
    async def stop_all_forwards(self) -> Tuple[bool, str]:
        """Remove nftables rules (async wrapper for compatibility)."""
        return self.remove_rules()
    
    async def restart_all_forwards(self) -> Tuple[bool, str]:
        """Re-apply nftables rules (async wrapper for compatibility)."""
        return self.apply_rules()
