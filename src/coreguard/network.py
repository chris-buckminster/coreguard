import json
import logging
import subprocess

from coreguard.config import DNS_BACKUP_FILE

logger = logging.getLogger("coreguard.network")


def get_active_interfaces() -> list[str]:
    """Get names of active network services on macOS."""
    result = subprocess.run(
        ["networksetup", "-listallnetworkservices"],
        capture_output=True,
        text=True,
    )
    services = []
    for line in result.stdout.splitlines()[1:]:  # Skip "An asterisk..." header
        line = line.strip()
        if line and not line.startswith("*"):  # Skip disabled services
            services.append(line)
    return services


def get_current_dns(service: str) -> list[str]:
    """Get current DNS servers for a network service."""
    result = subprocess.run(
        ["networksetup", "-getdnsservers", service],
        capture_output=True,
        text=True,
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
    """Point all active interfaces to 127.0.0.1."""
    backup_dns_settings()
    for service in get_active_interfaces():
        try:
            subprocess.run(
                ["networksetup", "-setdnsservers", service, "127.0.0.1"],
                check=True,
                capture_output=True,
            )
            logger.info("Set DNS for '%s' to 127.0.0.1", service)
        except subprocess.CalledProcessError as e:
            logger.warning("Failed to set DNS for '%s': %s", service, e)


def restore_dns() -> None:
    """Restore DNS settings from backup."""
    if not DNS_BACKUP_FILE.exists():
        logger.warning("No DNS backup file found, cannot restore")
        return

    backup = json.loads(DNS_BACKUP_FILE.read_text())
    for service, servers in backup.items():
        try:
            if servers:
                subprocess.run(
                    ["networksetup", "-setdnsservers", service] + servers,
                    check=True,
                    capture_output=True,
                )
            else:
                # Reset to DHCP-provided DNS
                subprocess.run(
                    ["networksetup", "-setdnsservers", service, "Empty"],
                    check=True,
                    capture_output=True,
                )
            logger.info("Restored DNS for '%s'", service)
        except subprocess.CalledProcessError as e:
            logger.warning("Failed to restore DNS for '%s': %s", service, e)

    DNS_BACKUP_FILE.unlink(missing_ok=True)
    logger.info("DNS settings restored")

    # Flush macOS DNS cache
    flush_dns_cache()


def flush_dns_cache() -> None:
    """Flush the macOS DNS cache."""
    try:
        subprocess.run(["dscacheutil", "-flushcache"], capture_output=True)
        subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True)
        logger.info("DNS cache flushed")
    except Exception as e:
        logger.warning("Failed to flush DNS cache: %s", e)
