import subprocess
import logging
from pathlib import Path
from typing import List, Tuple

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# HAProxy configuration paths
HAPROXY_CONFIG_DIR = Path("/etc/haproxy")
HAPROXY_CONFIG_FILE = HAPROXY_CONFIG_DIR / "vortexl2.cfg"
HAPROXY_STATS_FILE = Path("/var/lib/vortexl2/haproxy-stats")
HAPROXY_SOCKET = Path("/var/run/haproxy.sock")

class HAProxyManager:
    """Manages HAProxy for port forwarding."""
    
    def __init__(self, config):
        self.config = config
        self.haproxy_config_path = HAPROXY_CONFIG_FILE
    
    def _generate_haproxy_config(self, ports: List[int], remote_ip: str) -> str:
        """Generate HAProxy configuration dynamically for the given ports."""
        config = """
# Auto-generated HAProxy config for vortexl2
global
    maxconn 10000
    log stdout local0
    log stdout local1 notice
    chroot /var/lib/haproxy
    stats socket /var/run/haproxy.sock mode 660 level admin
    stats timeout 30s
    daemon

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    option  redispatch
    retries 3
    timeout connect 5000
    timeout client  50000
    timeout server  50000
"""
        for port in ports:
            backend_name = f"backend_{port}"
            frontend_name = f"frontend_{port}"

            config += f"""
backend {backend_name}
    balance roundrobin
    mode tcp
    server remote_host {remote_ip}:{port} check
    default-server inter 10s fall 3 rise 2

frontend {frontend_name}
    mode tcp
    bind 0.0.0.0:{port}
    default_backend {backend_name}
"""
        return config
    
    def _write_config_file(self, config_content: str) -> bool:
        """Write HAProxy configuration to file."""
        try:
            HAPROXY_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            
            # Write with temp file for atomicity
            temp_file = HAPROXY_CONFIG_FILE.with_suffix('.cfg.tmp')
            with open(temp_file, 'w') as f:
                f.write(config_content)
            
            # Validate configuration
            result = subprocess.run(
                ["haproxy", "-c", "-f", str(temp_file)],
                capture_output=True,
                timeout=10,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"HAProxy config validation failed:\n{result.stderr}")
                temp_file.unlink()
                return False
            
            # Move temp file to actual location
            temp_file.replace(HAPROXY_CONFIG_FILE)
            logger.info(f"Generated HAProxy config: {HAPROXY_CONFIG_FILE}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to write HAProxy config: {e}")
            return False
    
    def _reload_haproxy(self) -> bool:
        """Reload HAProxy configuration gracefully."""
        try:
            # Use systemctl if available, otherwise direct command
            result = subprocess.run(
                ["systemctl", "reload", "haproxy"],
                capture_output=True,
                timeout=10
            )
            
            if result.returncode != 0:
                # Try direct reload
                result = subprocess.run(
                    ["haproxy", "-f", str(HAPROXY_CONFIG_FILE), "-p", "/var/run/haproxy.pid", "-sf", "$(cat /var/run/haproxy.pid 2>/dev/null)"],
                    shell=False,
                    capture_output=True,
                    timeout=10
                )
                
                if result.returncode != 0:
                    logger.error(f"HAProxy reload failed: {result.stderr.decode()}")
                    return False
            
            logger.info("HAProxy reloaded successfully")
            return True
            
        except subprocess.TimeoutExpired:
            logger.error("HAProxy reload timeout")
            return False
        except Exception as e:
            logger.error(f"Failed to reload HAProxy: {e}")
            return False
    
    def create_forward(self, ports: List[int], remote_ip: str) -> Tuple[bool, str]:
        """Create port forwards using HAProxy."""
        # Generate the new HAProxy configuration
        config = self._generate_haproxy_config(ports, remote_ip)
        
        # Write the new configuration to the file
        if not self._write_config_file(config):
            return False, "Failed to write HAProxy configuration"
        
        # Reload HAProxy to apply the new configuration
        if not self._reload_haproxy():
            return False, "Failed to reload HAProxy"
        
        return True, f"Port forwards for ports {', '.join(map(str, ports))} created successfully."
    
    def remove_forward(self, ports: List[int]) -> Tuple[bool, str]:
        """Remove port forwards by updating HAProxy configuration."""
        # Get current configuration and remove the relevant entries
        current_config = self._generate_haproxy_config(ports, self.config.remote_forward_ip)
        
        # Write updated configuration
        if not self._write_config_file(current_config):
            return False, "Failed to update HAProxy configuration"
        
        # Reload HAProxy to apply changes
        if not self._reload_haproxy():
            return False, "Failed to reload HAProxy"
        
        return True, f"Port forwards for ports {', '.join(map(str, ports))} removed successfully."

    def list_forwards(self) -> str:
        """List all active port forwards."""
        return "Listing active port forwards is not implemented yet."

