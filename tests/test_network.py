from unittest.mock import patch, MagicMock
from coreguard.network import get_active_interfaces, get_current_dns, get_physical_interfaces


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
