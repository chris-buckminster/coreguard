import logging
import subprocess

logger = logging.getLogger("coreguard.notify")


def send_notification(title: str, message: str, sound: bool = True) -> None:
    """Send a macOS notification center alert via osascript."""
    sound_str = ', sound name "Basso"' if sound else ""
    script = f'display notification "{message}" with title "{title}"{sound_str}'
    try:
        subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            timeout=5,
        )
    except Exception as e:
        logger.debug("Failed to send notification: %s", e)


def notify_startup_failure(reason: str) -> None:
    """Alert that coreguard failed to start."""
    send_notification("Coreguard Failed to Start", reason)


def notify_dns_misconfigured() -> None:
    """Alert that system DNS is not pointing to coreguard."""
    send_notification(
        "Coreguard DNS Issue",
        "System DNS is not pointing to 127.0.0.1. Ad blocking may not be active.",
    )


def notify_lists_update_failed() -> None:
    """Alert that filter list update failed."""
    send_notification(
        "Coreguard Update Failed",
        "Could not update filter lists. Using cached versions.",
    )
