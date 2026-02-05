#!/usr/bin/env python3
"""
VortexL2 - L2TPv3 Tunnel Manager

Main entry point and CLI handler.
"""

import sys
import os
import argparse
import subprocess
import signal

# Ensure we can import the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vortexl2 import __version__
from vortexl2.config import TunnelConfig, ConfigManager, GlobalConfig
from vortexl2.tunnel import TunnelManager
from vortexl2.forward import get_forward_manager, get_forward_mode, set_forward_mode
from vortexl2 import ui


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print("\n")
    ui.console.print("[yellow]Interrupted. Goodbye![/]")
    sys.exit(0)


def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        ui.show_error("VortexL2 must be run as root (use sudo)")
        sys.exit(1)


def restart_forward_daemon():
    """Restart the forward daemon service to pick up config changes.
    
    Only starts HAProxy if forward mode is 'haproxy'.
    """
    mode = get_forward_mode()
    
    # Only start HAProxy if in haproxy mode
    if mode == "haproxy":
        subprocess.run(
            "systemctl start haproxy",
            shell=True,
            capture_output=True
        )
    
    # Restart the forward daemon
    subprocess.run(
        "systemctl restart vortexl2-forward-daemon",
        shell=True,
        capture_output=True
    )


def cmd_apply():
    """
    Apply all tunnel configurations (idempotent).
    Used by systemd service on boot.
    Note: Port forwarding is managed by the forward-daemon service
    """
    manager = ConfigManager()
    tunnels = manager.get_all_tunnels()
    
    if not tunnels:
        print("VortexL2: No tunnels configured, skipping")
        return 0
    
    errors = 0
    for config in tunnels:
        if not config.is_configured():
            print(f"VortexL2: Tunnel '{config.name}' not fully configured, skipping")
            continue
        
        tunnel = TunnelManager(config)
        
        # Setup tunnel
        success, msg = tunnel.full_setup()
        print(f"Tunnel '{config.name}': {msg}")
        
        if not success:
            errors += 1
            continue
    
    print("VortexL2: Tunnel setup complete. Port forwarding managed by forward-daemon service")
    return 1 if errors > 0 else 0


def handle_prerequisites():
    """Handle prerequisites installation."""
    ui.show_banner()
    ui.show_info("Installing prerequisites...")
    
    # Use temp config for prerequisites (they're system-wide)
    tunnel = TunnelManager(TunnelConfig("temp"))
    
    success, msg = tunnel.install_prerequisites()
    ui.show_output(msg, "Prerequisites Installation")
    
    if success:
        ui.show_success("Prerequisites installed successfully")
    else:
        ui.show_error(msg)
    
    ui.wait_for_enter()


def handle_create_tunnel(manager: ConfigManager):
    """Handle tunnel creation (config + start)."""
    ui.show_banner()
    
    # Ask for side first
    side = ui.prompt_tunnel_side()
    if not side:
        return
    
    # Get tunnel name
    name = ui.prompt_tunnel_name()
    if not name:
        return
    
    if manager.tunnel_exists(name):
        ui.show_error(f"Tunnel '{name}' already exists")
        ui.wait_for_enter()
        return
    
    # Create tunnel config in memory (not saved yet)
    config = manager.create_tunnel(name)
    ui.show_info(f"Tunnel '{name}' will use interface {config.interface_name}")
    
    # Configure tunnel based on side
    if not ui.prompt_tunnel_config(config, side, manager):
        # User cancelled or error - no config file was created
        ui.show_error("Configuration cancelled.")
        ui.wait_for_enter()
        return
    
    # Start tunnel
    ui.show_info("Starting tunnel...")
    tunnel = TunnelManager(config)
    success, msg = tunnel.full_setup()
    ui.show_output(msg, "Tunnel Setup")
    
    if success:
        # Only save config after successful tunnel creation
        config.save()
        ui.show_success(f"Tunnel '{name}' created and started successfully!")
    else:
        ui.show_error("Tunnel creation failed. Config not saved.")
    
    ui.wait_for_enter()


def handle_delete_tunnel(manager: ConfigManager):
    """Handle tunnel deletion (stop + remove config)."""
    ui.show_banner()
    ui.show_tunnel_list(manager)
    
    tunnels = manager.list_tunnels()
    if not tunnels:
        ui.show_warning("No tunnels to delete")
        ui.wait_for_enter()
        return
    
    selected = ui.prompt_select_tunnel(manager)
    if not selected:
        return
    
    if not ui.confirm(f"Are you sure you want to delete tunnel '{selected}'?", default=False):
        return
    
    # Stop tunnel first
    config = manager.get_tunnel(selected)
    if config:
        tunnel = TunnelManager(config)
        forward = ForwardManager(config)
        
        # Remove all port forwards from config
        if config.forwarded_ports:
            ui.show_info("Clearing port forwards from config...")
            ports_to_remove = list(config.forwarded_ports)  # Copy list since we're modifying it
            for port in ports_to_remove:
                forward.remove_forward(port)
            ui.show_success(f"Removed {len(ports_to_remove)} port forward(s) from config")
        
        # Stop tunnel
        ui.show_info("Stopping tunnel...")
        success, msg = tunnel.full_teardown()
        ui.show_output(msg, "Tunnel Teardown")
    
    # Delete config
    manager.delete_tunnel(selected)
    ui.show_success(f"Tunnel '{selected}' deleted")
    ui.wait_for_enter()


def handle_list_tunnels(manager: ConfigManager):
    """Handle listing all tunnels."""
    ui.show_banner()
    ui.show_tunnel_list(manager)
    ui.wait_for_enter()


def handle_forwards_menu(manager: ConfigManager):
    """Handle port forwards submenu."""
    ui.show_banner()
    
    # Select tunnel for forwards
    config = ui.prompt_select_tunnel_for_forwards(manager)
    if not config:
        return
    
    while True:
        ui.show_banner()
        
        # Get current forward mode
        current_mode = get_forward_mode()
        
        # Get the appropriate manager based on mode
        forward = get_forward_manager(config)
        
        ui.console.print(f"[bold]Managing forwards for tunnel: [magenta]{config.name}[/][/]\n")
        
        if current_mode == "none":
            ui.console.print("[yellow]⚠ Port forwarding is DISABLED. Select option 8 to enable.[/]\n")
        else:
            ui.console.print(f"[green]Forward mode: {current_mode.upper()}[/]\n")
        
        # Show current forwards if manager is available
        if forward:
            forwards = forward.list_forwards()
            if forwards:
                ui.show_forwards_list(forwards)
        else:
            # Show config-only forwards when mode is none
            from vortexl2.haproxy_manager import HAProxyManager
            temp_manager = HAProxyManager(config)
            forwards = temp_manager.list_forwards()
            if forwards:
                ui.show_forwards_list(forwards)
        
        choice = ui.show_forwards_menu(current_mode)
        
        if choice == "0":
            break
        elif choice == "1":
            # Add forwards (to config only)
            ports = ui.prompt_ports()
            if ports:
                # Always use HAProxyManager to add to config (it just updates YAML)
                from vortexl2.haproxy_manager import HAProxyManager
                config_manager = HAProxyManager(config)
                success, msg = config_manager.add_multiple_forwards(ports)
                ui.show_output(msg, "Add Forwards to Config")
                if current_mode != "none":
                    restart_forward_daemon()
                    ui.show_success("Forwards added. Daemon restarted to apply changes.")
                else:
                    ui.show_info("Forwards saved to config. Enable forwarding mode to activate.")
            ui.wait_for_enter()
        elif choice == "2":
            # Remove forwards (from config)
            ports = ui.prompt_ports()
            if ports:
                from vortexl2.haproxy_manager import HAProxyManager
                config_manager = HAProxyManager(config)
                success, msg = config_manager.remove_multiple_forwards(ports)
                ui.show_output(msg, "Remove Forwards from Config")
                if current_mode != "none":
                    restart_forward_daemon()
                    ui.show_success("Forwards removed. Daemon restarted to apply changes.")
            ui.wait_for_enter()
        elif choice == "3":
            # List forwards (already shown above)
            ui.wait_for_enter()
        elif choice == "4":
            # Restart daemon
            if current_mode == "none":
                ui.show_error("Port forwarding is disabled. Enable a mode first.")
            else:
                restart_forward_daemon()
                ui.show_success("Forward daemon restarted.")
            ui.wait_for_enter()
        elif choice == "5":
            # Stop daemon
            subprocess.run("systemctl stop vortexl2-forward-daemon", shell=True)
            ui.show_success("Forward daemon stopped.")
            ui.wait_for_enter()
        elif choice == "6":
            # Start daemon
            if current_mode == "none":
                ui.show_error("Port forwarding is disabled. Enable a mode first.")
            else:
                subprocess.run("systemctl start vortexl2-forward-daemon", shell=True)
                ui.show_success("Forward daemon started.")
            ui.wait_for_enter()
        elif choice == "7":
            # Validate and reload
            if current_mode == "none":
                ui.show_error("Port forwarding is disabled. Enable a mode first.")
            elif forward:
                ui.show_info("Validating configuration and reloading...")
                success, msg = forward.validate_and_reload()
                ui.show_output(msg, "Validate & Reload")
                if success:
                    ui.show_success("Reloaded successfully")
                else:
                    ui.show_error(msg)
            ui.wait_for_enter()
        elif choice == "8":
            # Change forward mode
            mode_choice = ui.show_forward_mode_menu(current_mode)
            new_mode = None
            if mode_choice == "1":
                new_mode = "none"
            elif mode_choice == "2":
                new_mode = "haproxy"
            
            if new_mode and new_mode != current_mode:
                # Stop current forwarding before changing mode
                if current_mode != "none":
                    ui.show_info("Stopping current forwards...")
                    if forward:
                        forward.stop_all_forwards()
                    subprocess.run("systemctl stop vortexl2-forward-daemon", shell=True)
                
                # Set new mode
                set_forward_mode(new_mode)
                ui.show_success(f"Forward mode changed to: {new_mode.upper()}")
                
                # If enabling a mode, offer to start
                if new_mode != "none":
                    if ui.Confirm.ask("Start port forwarding now?", default=True):
                        restart_forward_daemon()
                        ui.show_success("Forward daemon started.")
            ui.wait_for_enter()


def handle_logs(manager: ConfigManager):
    """Handle log viewing."""
    ui.show_banner()
    
    services = [
        "vortexl2-tunnel.service",
        "vortexl2-forward-daemon.service"
    ]
    
    for service in services:
        result = subprocess.run(
            f"journalctl -u {service} -n 20 --no-pager",
            shell=True,
            capture_output=True,
            text=True
        )
        output = result.stdout or result.stderr or "No logs available"
        ui.show_output(output, f"Logs: {service}")
    
    ui.wait_for_enter()


def main_menu():
    """Main interactive menu loop."""
    check_root()
    
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Clear screen before starting
    ui.clear_screen()
    
    # Initialize config manager
    manager = ConfigManager()
    
    while True:
        ui.show_banner()
        choice = ui.show_main_menu()
        
        try:
            if choice == "0":
                ui.console.print("\n[bold green]Goodbye![/]\n")
                break
            elif choice == "1":
                handle_prerequisites()
            elif choice == "2":
                handle_create_tunnel(manager)
            elif choice == "3":
                handle_delete_tunnel(manager)
            elif choice == "4":
                handle_list_tunnels(manager)
            elif choice == "5":
                handle_forwards_menu(manager)
            elif choice == "6":
                handle_logs(manager)
            else:
                ui.show_warning("Invalid option")
                ui.wait_for_enter()
        except KeyboardInterrupt:
            ui.console.print("\n[yellow]Interrupted[/]")
            continue
        except Exception as e:
            ui.show_error(f"Error: {e}")
            ui.wait_for_enter()


def main():
    """CLI entry point."""
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="VortexL2 - L2TPv3 Tunnel Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  (none)     Open interactive management panel
  apply      Apply all tunnel configurations (used by systemd)

Examples:
  sudo vortexl2           # Open management panel
  sudo vortexl2 apply     # Apply all tunnels (for systemd)
        """
    )
    parser.add_argument(
        'command',
        nargs='?',
        choices=['apply'],
        help='Command to run'
    )
    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'VortexL2 {__version__}'
    )
    
    args = parser.parse_args()
    
    if args.command == 'apply':
        check_root()
        sys.exit(cmd_apply())
    else:
        main_menu()


if __name__ == "__main__":
    main()
