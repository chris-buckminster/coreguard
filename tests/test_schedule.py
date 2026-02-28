from datetime import datetime, time

from coreguard.config import Schedule
from coreguard.schedule import (
    collect_schedule_rules,
    get_active_schedules,
    is_schedule_active,
    parse_time,
)


class TestParseTime:
    def test_parse_normal(self):
        t = parse_time("09:30")
        assert t == time(9, 30)

    def test_parse_midnight(self):
        t = parse_time("00:00")
        assert t == time(0, 0)

    def test_parse_end_of_day(self):
        t = parse_time("23:59")
        assert t == time(23, 59)


class TestIsScheduleActive:
    def test_active_during_window(self):
        s = Schedule(name="test", start="09:00", end="17:00", days=["mon"])
        now = datetime(2026, 2, 23, 12, 0)  # Monday noon
        assert is_schedule_active(s, now) is True

    def test_inactive_outside_window(self):
        s = Schedule(name="test", start="09:00", end="17:00", days=["mon"])
        now = datetime(2026, 2, 23, 20, 0)  # Monday 8pm
        assert is_schedule_active(s, now) is False

    def test_inactive_wrong_day(self):
        s = Schedule(name="test", start="09:00", end="17:00", days=["tue"])
        now = datetime(2026, 2, 23, 12, 0)  # Monday noon
        assert is_schedule_active(s, now) is False

    def test_overnight_schedule_evening(self):
        """Overnight schedule (21:00-06:00) should be active at 22:00."""
        s = Schedule(name="night", start="21:00", end="06:00", days=["mon"])
        now = datetime(2026, 2, 23, 22, 0)  # Monday 10pm
        assert is_schedule_active(s, now) is True

    def test_overnight_schedule_morning(self):
        """Overnight schedule (21:00-06:00) should be active at 03:00."""
        s = Schedule(name="night", start="21:00", end="06:00", days=["tue"])
        now = datetime(2026, 2, 24, 3, 0)  # Tuesday 3am
        assert is_schedule_active(s, now) is True

    def test_overnight_schedule_inactive_midday(self):
        """Overnight schedule (21:00-06:00) should NOT be active at 12:00."""
        s = Schedule(name="night", start="21:00", end="06:00", days=["mon"])
        now = datetime(2026, 2, 23, 12, 0)  # Monday noon
        assert is_schedule_active(s, now) is False

    def test_disabled_schedule(self):
        s = Schedule(name="test", start="09:00", end="17:00", days=["mon"], enabled=False)
        now = datetime(2026, 2, 23, 12, 0)  # Monday noon
        assert is_schedule_active(s, now) is False

    def test_at_start_boundary(self):
        s = Schedule(name="test", start="09:00", end="17:00", days=["mon"])
        now = datetime(2026, 2, 23, 9, 0)  # Monday 9:00
        assert is_schedule_active(s, now) is True

    def test_at_end_boundary(self):
        s = Schedule(name="test", start="09:00", end="17:00", days=["mon"])
        now = datetime(2026, 2, 23, 17, 0)  # Monday 17:00
        assert is_schedule_active(s, now) is True


class TestGetActiveSchedules:
    def test_returns_active_only(self):
        schedules = [
            Schedule(name="active", start="09:00", end="17:00", days=["mon"]),
            Schedule(name="inactive", start="18:00", end="23:00", days=["mon"]),
        ]
        now = datetime(2026, 2, 23, 12, 0)  # Monday noon
        active = get_active_schedules(schedules, now)
        assert len(active) == 1
        assert active[0].name == "active"

    def test_empty_schedules(self):
        assert get_active_schedules([], datetime.now()) == []


class TestCollectScheduleRules:
    def test_collects_domains_and_patterns(self):
        schedules = [
            Schedule(
                name="work",
                block_domains=["reddit.com", "twitter.com"],
                block_patterns=["*.tiktok.com", "regex:^ads\\..*$"],
            ),
        ]
        domains, wildcards, regexes = collect_schedule_rules(schedules)
        assert "reddit.com" in domains
        assert "twitter.com" in domains
        assert "*.tiktok.com" in wildcards
        assert r"^ads\..*$" in regexes

    def test_collects_from_multiple_schedules(self):
        schedules = [
            Schedule(name="a", block_domains=["a.com"]),
            Schedule(name="b", block_domains=["b.com"], block_patterns=["*.c.com"]),
        ]
        domains, wildcards, regexes = collect_schedule_rules(schedules)
        assert "a.com" in domains
        assert "b.com" in domains
        assert "*.c.com" in wildcards

    def test_plain_patterns_go_to_domains(self):
        """block_patterns without * or regex: prefix are treated as domains."""
        schedules = [
            Schedule(name="test", block_patterns=["plain.com"]),
        ]
        domains, wildcards, regexes = collect_schedule_rules(schedules)
        assert "plain.com" in domains
        assert wildcards == []
        assert regexes == []
