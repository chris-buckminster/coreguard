import json
from pathlib import Path
from unittest.mock import patch, MagicMock, call

from coreguard.network import (
    backup_dns_settings,
    flush_dns_cache,
    get_active_interfaces,
    get_current_dns,
    get_physical_interfaces,
    restore_dns,
    set_dns_to_local,
)


class TestGetActiveInterfaces:
    @patch("coreguard.network.subprocess.run")
    def test_parses_interfaces(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nEthernet\n*Bluetooth PAN\n"
        )
        interfaces = get_active_interfaces()
        assert "Wi-Fi" in interfaces
        assert "Ethernet" in interfaces
        assert "Bluetooth PAN" not in interfaces  # disabled

    @patch("coreguard.network.subprocess.run")
    def test_empty_output(self, mock_run):
        mock_run.return_value = MagicMock(stdout="An asterisk (*) denotes...\n")
        interfaces = get_active_interfaces()
        assert interfaces == []


class TestGetPhysicalInterfaces:
    @patch("coreguard.network.subprocess.run")
    def test_filters_vpn_interfaces(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=(
                "An asterisk (*) denotes that a network service is disabled.\n"
                "(1) Wi-Fi\n"
                "(Hardware Port: Wi-Fi, Device: en0)\n"
                "\n"
                "(2) Ethernet\n"
                "(Hardware Port: Ethernet, Device: en1)\n"
                "\n"
                "(3) Corporate VPN\n"
                "(Hardware Port: L2TP, Device: ppp0)\n"
                "\n"
                "(4) iPhone USB\n"
                "(Hardware Port: iPhone USB, Device: en5)\n"
            )
        )
        interfaces = get_physical_interfaces()
        assert "Wi-Fi" in interfaces
        assert "Ethernet" in interfaces
        assert "iPhone USB" in interfaces
        assert "Corporate VPN" not in interfaces

    @patch("coreguard.network.subprocess.run")
    def test_filters_vpn_by_name(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=(
                "An asterisk (*) denotes that a network service is disabled.\n"
                "(1) Wi-Fi\n"
                "(Hardware Port: Wi-Fi, Device: en0)\n"
                "\n"
                "(2) WireGuard Tunnel\n"
                "(Hardware Port: WireGuard Tunnel, Device: utun3)\n"
            )
        )
        interfaces = get_physical_interfaces()
        assert "Wi-Fi" in interfaces
        assert "WireGuard Tunnel" not in interfaces

    @patch("coreguard.network.subprocess.run")
    def test_skips_disabled_services(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=(
                "An asterisk (*) denotes that a network service is disabled.\n"
                "(1) Wi-Fi\n"
                "(Hardware Port: Wi-Fi, Device: en0)\n"
                "\n"
                "(*) Thunderbolt Bridge\n"
                "(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n"
            )
        )
        interfaces = get_physical_interfaces()
        assert "Wi-Fi" in interfaces
        assert "Thunderbolt Bridge" not in interfaces


class TestGetCurrentDns:
    @patch("coreguard.network.subprocess.run")
    def test_returns_servers(self, mock_run):
        mock_run.return_value = MagicMock(stdout="8.8.8.8\n8.8.4.4\n")
        servers = get_current_dns("Wi-Fi")
        assert servers == ["8.8.8.8", "8.8.4.4"]

    @patch("coreguard.network.subprocess.run")
    def test_no_dns_set(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="There aren't any DNS Servers set on Wi-Fi.\n"
        )
        servers = get_current_dns("Wi-Fi")
        assert servers == []


class TestBackupDnsSettings:
    @patch("coreguard.network.DNS_BACKUP_FILE")
    @patch("coreguard.network.get_current_dns")
    @patch("coreguard.network.get_active_interfaces", return_value=["Wi-Fi", "Ethernet"])
    def test_backup_saves_all_interfaces(self, mock_ifaces, mock_dns, mock_file):
        mock_dns.side_effect = lambda svc: ["8.8.8.8"] if svc == "Wi-Fi" else []
        backup_dns_settings()
        written = mock_file.write_text.call_args[0][0]
        data = json.loads(written)
        assert data["Wi-Fi"] == ["8.8.8.8"]
        assert data["Ethernet"] == []


class TestSetDnsToLocal:
    @patch("coreguard.network.flush_dns_cache")
    @patch("coreguard.network.get_current_dns", return_value=["127.0.0.1"])
    @patch("coreguard.network.subprocess.run")
    @patch("coreguard.network.get_physical_interfaces", return_value=["Wi-Fi"])
    @patch("coreguard.network.backup_dns_settings")
    def test_sets_local_dns(self, mock_backup, mock_ifaces, mock_run, mock_dns, mock_flush):
        mock_run.return_value = MagicMock()
        set_dns_to_local()
        mock_backup.assert_called_once()
        # Should call networksetup -setdnsservers Wi-Fi 127.0.0.1
        mock_run.assert_called_with(
            ["networksetup", "-setdnsservers", "Wi-Fi", "127.0.0.1"],
            check=True,
            capture_output=True,
            timeout=10,
        )


class TestRestoreDns:
    @patch("coreguard.network.flush_dns_cache")
    @patch("coreguard.network.subprocess.run")
    @patch("coreguard.network.DNS_BACKUP_FILE")
    def test_restores_from_backup(self, mock_file, mock_run, mock_flush):
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = json.dumps({"Wi-Fi": ["8.8.8.8", "8.8.4.4"]})
        mock_run.return_value = MagicMock()
        restore_dns()
        mock_run.assert_any_call(
            ["networksetup", "-setdnsservers", "Wi-Fi", "8.8.8.8", "8.8.4.4"],
            check=True,
            capture_output=True,
            timeout=10,
        )
        mock_file.unlink.assert_called_once_with(missing_ok=True)

    @patch("coreguard.network.DNS_BACKUP_FILE")
    def test_missing_backup_warns(self, mock_file):
        mock_file.exists.return_value = False
        # Should not raise
        restore_dns()

    @patch("coreguard.network.flush_dns_cache")
    @patch("coreguard.network.subprocess.run")
    @patch("coreguard.network.DNS_BACKUP_FILE")
    def test_empty_servers_resets_to_dhcp(self, mock_file, mock_run, mock_flush):
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = json.dumps({"Wi-Fi": []})
        mock_run.return_value = MagicMock()
        restore_dns()
        mock_run.assert_any_call(
            ["networksetup", "-setdnsservers", "Wi-Fi", "Empty"],
            check=True,
            capture_output=True,
            timeout=10,
        )


class TestFlushDnsCache:
    @patch("coreguard.network.subprocess.run")
    def test_runs_flush_commands(self, mock_run):
        mock_run.return_value = MagicMock()
        flush_dns_cache()
        assert mock_run.call_count == 2
        mock_run.assert_any_call(
            ["dscacheutil", "-flushcache"],
            capture_output=True,
            timeout=10,
        )
        mock_run.assert_any_call(
            ["killall", "-HUP", "mDNSResponder"],
            capture_output=True,
            timeout=10,
        )

    @patch("coreguard.network.subprocess.run", side_effect=Exception("not found"))
    def test_handles_failure_gracefully(self, mock_run):
        # Should not raise
        flush_dns_cache()
