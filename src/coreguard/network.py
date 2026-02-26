import json
import logging
import re
import subprocess

from coreguard.config import DNS_BACKUP_FILE

logger = logging.getLogger("coreguard.network")

SUBPROCESS_TIMEOUT = 10  # seconds

# Hardware port types that correspond to physical network interfaces.
# VPN services use ports like "L2TP", "PPTP", "IPSec", or have no port at all.
_PHYSICAL_PORT_PATTERNS = re.compile(
    r"Wi-Fi|Ethernet|Thunderbolt|USB|FireWire|AirPort",
    re.IGNORECASE,
)

# Service names that indicate a VPN — used as a safety net alongside port checks.
_VPN_NAME_PATTERNS = re.compile(
    r"VPN|WireGuard|OpenVPN|IPSec|L2TP|PPTP|Cisco|Tailscale|Mullvad|NordVPN|ProtonVPN",
    re.IGNORECASE,
)


def get_active_interfaces() -> list[str]:
    """Get names of all active network services on macOS (including VPNs).

    Use this for diagnostics (doctor, status). For DNS modification,
    use get_physical_interfaces() instead to avoid breaking VPN DNS.
    """
    result = subprocess.run(
        ["networksetup", "-listallnetworkservices"],
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    services = []
    for line in result.stdout.splitlines()[1:]:  # Skip "An asterisk..." header
        line = line.strip()
        if line and not line.startswith("*"):  # Skip disabled services
            services.append(line)
    return services


def get_physical_interfaces() -> list[str]:
    """Get names of physical network services, excluding VPN tunnels.

    Parses `networksetup -listnetworkserviceorder` to check hardware port
    types. Only returns interfaces with physical ports (Wi-Fi, Ethernet,
    Thunderbolt, USB) and filters out VPN services by name as a safety net.
    """
    try:
        result = subprocess.run(
            ["networksetup", "-listnetworkserviceorder"],
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
    except Exception:
        # Fall back to all interfaces if the command fails
        return get_active_interfaces()

    physical = []
    lines = result.stdout.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Service lines look like: "(1) Wi-Fi" or "(*) Disabled Service"
        match = re.match(r"^\([\d*]+\)\s+(.+)$", line)
        if match:
            service_name = match.group(1)
            # Next line has the hardware port info
            hw_line = lines[i + 1].strip() if i + 1 < len(lines) else ""
            # Extract hardware port: "(Hardware Port: Wi-Fi, Device: en0)"
            port_match = re.search(r"Hardware Port:\s*([^,]+)", hw_line)
            hw_port = port_match.group(1).strip() if port_match else ""

            is_physical = bool(_PHYSICAL_PORT_PATTERNS.search(hw_port))
            is_vpn_name = bool(_VPN_NAME_PATTERNS.search(service_name))
            is_disabled = line.startswith("(*)")

            if is_physical and not is_vpn_name and not is_disabled:
                physical.append(service_name)
        i += 1

    return physical if physical else get_active_interfaces()


def get_current_dns(service: str) -> list[str]:
    """Get current DNS servers for a network service."""
    result = subprocess.run(
        ["networksetup", "-getdnsservers", service],
        capture_output=True,
        text=True,
        timeout=SUBPROCESS_TIMEOUT,
    )
    output = result.stdout.strip()
    if "no DNS" in output.lower() or "there aren't any" in output.lower():
        return []  # Using DHCP defaults
    return [line.strip() for line in output.splitlines() if line.strip()]


def backup_dns_settings() -> None:
    """Save current DNS settings for all interfaces."""
    backup = {}
    for service in get_active_interfaces():
        backup[service] = get_current_dns(service)
    DNS_BACKUP_FILE.write_text(json.dumps(backup, indent=2))
    logger.info("DNS settings backed up to %s", DNS_BACKUP_FILE)


def set_dns_to_local() -> None:
    """Point all physical interfaces to 127.0.0.1 (skips VPN tunnels)."""
    backup_dns_settings()
    interfaces = get_physical_interfaces()
    for service in interfaces:
        try:
            subprocess.run(
                ["networksetup", "-setdnsservers", service, "127.0.0.1"],
                check=True,
                capture_output=True,
                timeout=SUBPROCESS_TIMEOUT,
            )
            logger.info("Set DNS for '%s' to 127.0.0.1", service)
        except subprocess.CalledProcessError as e:
            logger.warning("Failed to set DNS for '%s': %s", service, e)
        except subprocess.TimeoutExpired:
            logger.warning("Timed out setting DNS for '%s'", service)

    # Verify DNS was actually set
    for service in interfaces:
        servers = get_current_dns(service)
        if servers and "127.0.0.1" not in servers:
            logger.warning("DNS for '%s' did not apply correctly: %s", service, servers)


def restore_dns() -> None:
    """Restore DNS settings from backup."""
    if not DNS_BACKUP_FILE.exists():
        logger.warning("No DNS backup file found, cannot restore")
        return

    try:
        backup = json.loads(DNS_BACKUP_FILE.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("DNS backup file is corrupt: %s", e)
        # Fall back to resetting all interfaces to DHCP
        for service in get_active_interfaces():
            try:
                subprocess.run(
                    ["networksetup", "-setdnsservers", service, "Empty"],
                    check=True,
                    capture_output=True,
                    timeout=SUBPROCESS_TIMEOUT,
                )
            except Exception:
                pass
        DNS_BACKUP_FILE.unlink(missing_ok=True)
        return

    for service, servers in backup.items():
        try:
            if servers:
                subprocess.run(
                    ["networksetup", "-setdnsservers", service] + servers,
                    check=True,
                    capture_output=True,
                    timeout=SUBPROCESS_TIMEOUT,
                )
            else:
                # Reset to DHCP-provided DNS
                subprocess.run(
                    ["networksetup", "-setdnsservers", service, "Empty"],
                    check=True,
                    capture_output=True,
                    timeout=SUBPROCESS_TIMEOUT,
                )
            logger.info("Restored DNS for '%s'", service)
        except subprocess.CalledProcessError as e:
            logger.warning("Failed to restore DNS for '%s': %s", service, e)
        except subprocess.TimeoutExpired:
            logger.warning("Timed out restoring DNS for '%s'", service)

    DNS_BACKUP_FILE.unlink(missing_ok=True)
    logger.info("DNS settings restored")

    # Flush macOS DNS cache
    flush_dns_cache()


def reapply_dns(service: str) -> bool:
    """Re-apply 127.0.0.1 DNS on a single interface. Returns True on success."""
    try:
        subprocess.run(
            ["networksetup", "-setdnsservers", service, "127.0.0.1"],
            check=True,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
        logger.info("Re-applied DNS for '%s' to 127.0.0.1", service)
        return True
    except Exception as e:
        logger.warning("Failed to re-apply DNS for '%s': %s", service, e)
        return False


def flush_dns_cache() -> None:
    """Flush the macOS DNS cache."""
    try:
        subprocess.run(["dscacheutil", "-flushcache"], capture_output=True, timeout=SUBPROCESS_TIMEOUT)
        subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True, timeout=SUBPROCESS_TIMEOUT)
        logger.info("DNS cache flushed")
    except Exception as e:
        logger.warning("Failed to flush DNS cache: %s", e)
