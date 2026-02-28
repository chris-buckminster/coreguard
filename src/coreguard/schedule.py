"""Schedule evaluation for time-based filtering."""

from datetime import datetime, time

from coreguard.config import Schedule


_DAY_MAP = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def parse_time(s: str) -> time:
    """Parse an 'HH:MM' string into a time object."""
    parts = s.strip().split(":")
    return time(int(parts[0]), int(parts[1]))


def is_schedule_active(schedule: Schedule, now: datetime | None = None) -> bool:
    """Check if a schedule is currently active based on enabled, day, and time."""
    if not schedule.enabled:
        return False

    if now is None:
        now = datetime.now()

    # Check day of week
    day_abbr = now.strftime("%a").lower()[:3]
    if day_abbr not in schedule.days:
        return False

    # Parse start/end times
    start = parse_time(schedule.start)
    end = parse_time(schedule.end)
    current = now.time()

    # Handle overnight spans (e.g. 21:00 - 06:00)
    if start <= end:
        return start <= current <= end
    else:
        return current >= start or current <= end


def get_active_schedules(
    schedules: list[Schedule], now: datetime | None = None
) -> list[Schedule]:
    """Return all currently active schedules."""
    return [s for s in schedules if is_schedule_active(s, now)]


def collect_schedule_rules(
    active: list[Schedule],
) -> tuple[list[str], list[str], list[str]]:
    """Extract blocking rules from active schedules.

    Returns (domains, wildcards, regexes) to be applied as overlay.
    """
    domains: list[str] = []
    wildcards: list[str] = []
    regexes: list[str] = []

    for schedule in active:
        domains.extend(schedule.block_domains)
        for pattern in schedule.block_patterns:
            if pattern.startswith("regex:"):
                regexes.append(pattern[6:])
            elif "*" in pattern:
                wildcards.append(pattern)
            else:
                domains.append(pattern)

    return domains, wildcards, regexes
