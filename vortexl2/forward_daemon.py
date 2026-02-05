import asyncio
import logging
import signal
import sys
import subprocess
from pathlib import Path

# Ensure we can import the package
sys.path.insert(0, str(Path(__file__).parent.parent))

from vortexl2.config import ConfigManager
from vortexl2.haproxy_manager import HAProxyManager  # Import HAProxyManager
from vortexl2.forward import ForwardManager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/vortexl2/forward-daemon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ForwardDaemon:
    """Manages the forward daemon."""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.forward_managers = {}
        self.running = False
    
    async def start(self):
        """Start the forward daemon."""
        logger.info("Starting VortexL2 Forward Daemon")
        
        # Ensure HAProxy is running before we try to manage it
        logger.info("Ensuring HAProxy service is running...")
        result = subprocess.run(
            "systemctl start haproxy",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            logger.warning(f"Could not ensure HAProxy is running: {result.stderr}")
        
        self.running = True
        
        # Get all tunnel configurations
        tunnels = self.config_manager.get_all_tunnels()
        
        if not tunnels:
            logger.warning("No tunnels configured")
            return
        
        # Create a single forward manager that manages HAProxy for all tunnels
        forward_manager = ForwardManager(self.config_manager)
        self.forward_managers['haproxy_manager'] = forward_manager

        logger.info("Starting HAProxy forwards for all configured tunnels")
        success, msg = await forward_manager.start_all_forwards()
        if not success:
            logger.error(f"Failed to start port forwards: {msg}")
        else:
            logger.info(msg)
        
        logger.info("Forward Daemon started successfully")
        
        # Keep running
        try:
            while self.running:
                await asyncio.sleep(1)
        except Exception as e:
            logger.error(f"Error in forward daemon: {e}")
    
    async def stop(self):
        """Stop the forward daemon."""
        logger.info("Stopping VortexL2 Forward Daemon")
        self.running = False
        
        # Stop the HAProxy manager
        fm = self.forward_managers.get('haproxy_manager')
        if fm:
            logger.info("Stopping HAProxy forwards")
            await fm.stop_all_forwards()
        
        logger.info("Forward Daemon stopped")

# Main entry point for the forward daemon
async def main():
    """Main entry point."""
    daemon = ForwardDaemon()
    
    # Setup signal handlers
    def handle_signal(sig, frame):
        logger.info(f"Received signal {sig}")
        asyncio.create_task(daemon.stop())
    
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    
    try:
        await daemon.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        await daemon.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
