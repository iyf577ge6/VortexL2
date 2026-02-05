#!/usr/bin/env python3
"""
VortexL2 Forward Daemon

Applies nftables rules for kernel-level port forwarding on startup.
This replaces the asyncio-based user-space proxy with kernel NAT.
"""

from __future__ import annotations

import logging
import signal
import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vortexl2.config import ConfigManager
from vortexl2.forward import ForwardManager

# Ensure log directory exists
LOG_DIR = Path("/var/log/vortexl2")
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / 'forward-daemon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ForwardDaemon:
    """Manages nftables-based port forwarding."""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.running = False
    
    def apply_all_rules(self) -> bool:
        """Apply nftables rules for all configured tunnels."""
        logger.info("Applying nftables port forwarding rules")
        
        tunnels = self.config_manager.get_all_tunnels()
        
        if not tunnels:
            logger.warning("No tunnels configured")
            return True
        
        success_count = 0
        for tunnel_config in tunnels:
            if not tunnel_config.is_configured():
                logger.warning(f"Tunnel '{tunnel_config.name}' not fully configured, skipping")
                continue
            
            if not tunnel_config.forwarded_ports:
                logger.debug(f"Tunnel '{tunnel_config.name}' has no forwarded ports")
                continue
            
            forward_manager = ForwardManager(tunnel_config)
            
            logger.info(f"Applying rules for tunnel '{tunnel_config.name}': "
                       f"{len(tunnel_config.forwarded_ports)} ports -> {tunnel_config.remote_forward_ip}")
            
            success, msg = forward_manager.apply_rules()
            if success:
                logger.info(f"Tunnel '{tunnel_config.name}': {msg}")
                success_count += 1
            else:
                logger.error(f"Tunnel '{tunnel_config.name}': {msg}")
        
        logger.info(f"Applied rules for {success_count} tunnel(s)")
        return success_count > 0
    
    def start(self):
        """Start the daemon - apply rules and stay alive."""
        logger.info("Starting VortexL2 Forward Daemon (nftables)")
        self.running = True
        
        # Apply rules on startup
        self.apply_all_rules()
        
        logger.info("Forward Daemon running (nftables rules applied)")
        
        # Keep running to maintain systemd service status
        try:
            while self.running:
                time.sleep(60)
                # Periodic health check - verify rules are still loaded
                self._health_check()
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        
        logger.info("Forward Daemon stopped")
    
    def _health_check(self):
        """Periodically verify rules are still active."""
        try:
            import subprocess
            result = subprocess.run(
                "nft list table ip vortexl2_nat 2>/dev/null",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                logger.warning("nftables rules not found, re-applying...")
                self.apply_all_rules()
        except Exception as e:
            logger.debug(f"Health check error: {e}")
    
    def stop(self):
        """Stop the daemon."""
        logger.info("Stopping VortexL2 Forward Daemon")
        self.running = False


def main():
    """Main entry point."""
    daemon = ForwardDaemon()
    
    # Setup signal handlers
    def handle_signal(sig, frame):
        logger.info(f"Received signal {sig}")
        daemon.stop()
    
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    
    try:
        daemon.start()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
