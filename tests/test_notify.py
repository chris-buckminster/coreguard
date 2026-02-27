from unittest.mock import patch, MagicMock

from coreguard.notify import (
    _escape_applescript,
    send_notification,
    notify_startup_failure,
    notify_dns_misconfigured,
    notify_lists_update_failed,
)


class TestEscapeApplescript:
    def test_escapes_backslashes(self):
        assert _escape_applescript("path\\to\\file") == "path\\\\to\\\\file"

    def test_escapes_quotes(self):
        assert _escape_applescript('say "hello"') == 'say \\"hello\\"'

    def test_escapes_combined(self):
        assert _escape_applescript('a\\b"c') == 'a\\\\b\\"c'

    def test_no_escaping_needed(self):
        assert _escape_applescript("plain text") == "plain text"


class TestSendNotification:
    @patch("coreguard.notify.subprocess.run")
    def test_calls_osascript(self, mock_run):
        send_notification("Title", "Message")
        mock_run.assert_called_once()
        args = mock_run.call_args
        assert args[0][0][0] == "osascript"
        assert args[0][0][1] == "-e"
        assert "Title" in args[0][0][2]
        assert "Message" in args[0][0][2]
        assert "Basso" in args[0][0][2]

    @patch("coreguard.notify.subprocess.run")
    def test_no_sound(self, mock_run):
        send_notification("Title", "Message", sound=False)
        script = mock_run.call_args[0][0][2]
        assert "Basso" not in script

    @patch("coreguard.notify.subprocess.run")
    def test_handles_exception(self, mock_run):
        mock_run.side_effect = OSError("osascript not found")
        # Should not raise
        send_notification("Title", "Message")


class TestNotificationWrappers:
    @patch("coreguard.notify.send_notification")
    def test_startup_failure(self, mock_send):
        notify_startup_failure("port 53 in use")
        mock_send.assert_called_once_with("Coreguard Failed to Start", "port 53 in use")

    @patch("coreguard.notify.send_notification")
    def test_dns_misconfigured(self, mock_send):
        notify_dns_misconfigured()
        mock_send.assert_called_once()
        assert "127.0.0.1" in mock_send.call_args[0][1]

    @patch("coreguard.notify.send_notification")
    def test_lists_update_failed(self, mock_send):
        notify_lists_update_failed()
        mock_send.assert_called_once()
        assert "filter lists" in mock_send.call_args[0][1].lower()
