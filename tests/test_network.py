from unittest.mock import patch, MagicMock
from coreguard.network import get_active_interfaces, get_current_dns


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
