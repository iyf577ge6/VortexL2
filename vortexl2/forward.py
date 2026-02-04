"""
VortexL2 Port Forward Management

Handles socat-based TCP port forwarding with systemd service management.
Each port forward gets its own service file with the correct remote IP.
"""

import os
import subprocess
from pathlib import Path
from typing import List, Tuple, Dict, Optional


SYSTEMD_DIR = Path("/etc/systemd/system")

# Service file template - one per port (not a systemd template anymore)
SERVICE_TEMPLATE = """[Unit]
Description=VortexL2 Port Forward - Port {port}
After=network.target
Requires=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP4-LISTEN:{port},reuseaddr,fork TCP4:{remote_ip}:{port}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def run_command(cmd: str) -> Tuple[bool, str]:
    """Execute a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        output = result.stdout.strip() or result.stderr.strip()
        return result.returncode == 0, output
    except Exception as e:
        return False, str(e)


class ForwardManager:
    """Manages socat port forwarding services."""
    
    def __init__(self, config):
        self.config = config
    
    def _get_service_name(self, port: int) -> str:
        """Get systemd service name for a port."""
        return f"vortexl2-fwd-{port}.service"
    
    def _get_service_path(self, port: int) -> Path:
        """Get path to the service file for a port."""
        return SYSTEMD_DIR / self._get_service_name(port)
    
    def create_forward(self, port: int) -> Tuple[bool, str]:
        """Create and start a port forward service."""
        remote_ip = self.config.remote_forward_ip
        if not remote_ip:
            return False, "Remote forward IP not configured"
        
        service_path = self._get_service_path(port)
        service_name = self._get_service_name(port)
        
        # Create service file with correct remote IP
        service_content = SERVICE_TEMPLATE.format(port=port, remote_ip=remote_ip)
        
        try:
            with open(service_path, 'w') as f:
                f.write(service_content)
        except Exception as e:
            return False, f"Failed to create service file: {e}"
        
        # Reload systemd
        run_command("systemctl daemon-reload")
        
        # Enable and start the service
        success, output = run_command(f"systemctl enable --now {service_name}")
        if not success:
            return False, f"Failed to start forward for port {port}: {output}"
        
        # Add to config
        self.config.add_port(port)
        
        return True, f"Port forward for {port} created (-> {remote_ip}:{port})"
    
    def remove_forward(self, port: int) -> Tuple[bool, str]:
        """Stop, disable and remove a port forward service."""
        service_name = self._get_service_name(port)
        service_path = self._get_service_path(port)
        
        # Stop and disable
        run_command(f"systemctl stop {service_name}")
        run_command(f"systemctl disable {service_name}")
        
        # Remove service file
        if service_path.exists():
            service_path.unlink()
        
        # Reload systemd
        run_command("systemctl daemon-reload")
        
        # Remove from config
        self.config.remove_port(port)
        
        return True, f"Port forward for {port} removed"
    
    def add_multiple_forwards(self, ports_str: str) -> Tuple[bool, str]:
        """Add multiple port forwards from comma-separated string."""
        results = []
        ports = [p.strip() for p in ports_str.split(',') if p.strip()]
        
        for port_str in ports:
            try:
                port = int(port_str)
                success, msg = self.create_forward(port)
                results.append(f"Port {port}: {msg}")
            except ValueError:
                results.append(f"Port '{port_str}': Invalid port number")
        
        return True, "\n".join(results)
    
    def remove_multiple_forwards(self, ports_str: str) -> Tuple[bool, str]:
        """Remove multiple port forwards from comma-separated string."""
        results = []
        ports = [p.strip() for p in ports_str.split(',') if p.strip()]
        
        for port_str in ports:
            try:
                port = int(port_str)
                success, msg = self.remove_forward(port)
                results.append(f"Port {port}: {msg}")
            except ValueError:
                results.append(f"Port '{port_str}': Invalid port number")
        
        return True, "\n".join(results)
    
    def list_forwards(self) -> List[Dict]:
        """List all configured port forwards with their status."""
        forwards = []
        
        for port in self.config.forwarded_ports:
            service_name = self._get_service_name(port)
            
            # Check service status
            success, output = run_command(f"systemctl is-active {service_name}")
            status = output if success else "inactive"
            
            # Check if enabled
            success, output = run_command(f"systemctl is-enabled {service_name}")
            enabled = output if success else "disabled"
            
            forwards.append({
                "port": port,
                "status": status,
                "enabled": enabled,
                "remote": f"{self.config.remote_forward_ip}:{port}"
            })
        
        return forwards
    
    def start_all_forwards(self) -> Tuple[bool, str]:
        """Start all configured port forwards."""
        results = []
        
        for port in self.config.forwarded_ports:
            service_name = self._get_service_name(port)
            service_path = self._get_service_path(port)
            
            # If service file doesn't exist, recreate it
            if not service_path.exists():
                success, msg = self.create_forward(port)
                results.append(f"Port {port}: recreated and started")
            else:
                success, output = run_command(f"systemctl start {service_name}")
                if success:
                    results.append(f"Port {port}: started")
                else:
                    results.append(f"Port {port}: failed to start - {output}")
        
        if not results:
            return True, "No port forwards configured"
        
        return True, "\n".join(results)
    
    def stop_all_forwards(self) -> Tuple[bool, str]:
        """Stop all configured port forwards."""
        results = []
        
        for port in self.config.forwarded_ports:
            service_name = self._get_service_name(port)
            success, output = run_command(f"systemctl stop {service_name}")
            if success:
                results.append(f"Port {port}: stopped")
            else:
                results.append(f"Port {port}: failed to stop - {output}")
        
        if not results:
            return True, "No port forwards configured"
        
        return True, "\n".join(results)
    
    def restart_all_forwards(self) -> Tuple[bool, str]:
        """Restart all configured port forwards."""
        results = []
        
        for port in self.config.forwarded_ports:
            service_name = self._get_service_name(port)
            service_path = self._get_service_path(port)
            
            # If service file doesn't exist or IP changed, recreate it
            if not service_path.exists():
                success, msg = self.create_forward(port)
                results.append(f"Port {port}: recreated")
            else:
                # Update service file with current remote IP
                remote_ip = self.config.remote_forward_ip
                service_content = SERVICE_TEMPLATE.format(port=port, remote_ip=remote_ip)
                
                with open(service_path, 'w') as f:
                    f.write(service_content)
                
                run_command("systemctl daemon-reload")
                success, output = run_command(f"systemctl restart {service_name}")
                if success:
                    results.append(f"Port {port}: restarted")
                else:
                    results.append(f"Port {port}: failed - {output}")
        
        if not results:
            return True, "No port forwards configured"
        
        return True, "\n".join(results)
