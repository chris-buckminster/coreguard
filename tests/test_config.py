from coreguard.config import Config, Schedule, UpstreamProvider, _config_to_dict, _dict_to_config, load_config, save_config


class TestConfig:
    def test_defaults(self):
        config = Config()
        assert config.upstream_mode == "doh"
        assert config.listen_port == 53
        assert config.listen_address == "127.0.0.1"
        assert config.update_interval_hours == 24
        assert len(config.filter_lists) > 0
        assert len(config.upstream_providers) == 3
        assert config.upstream_providers[0].name == "cloudflare"
        assert config.upstream_providers[1].name == "google"
        assert config.upstream_providers[2].name == "quad9"

    def test_roundtrip(self):
        config = Config()
        d = _config_to_dict(config)
        restored = _dict_to_config(d)
        assert restored.upstream_mode == config.upstream_mode
        assert restored.listen_port == config.listen_port
        assert len(restored.filter_lists) == len(config.filter_lists)
        assert len(restored.upstream_providers) == len(config.upstream_providers)
        for orig, rest in zip(config.upstream_providers, restored.upstream_providers):
            assert rest.name == orig.name
            assert rest.doh == orig.doh
            assert rest.dot == orig.dot
            assert rest.plain == orig.plain

    def test_partial_config(self):
        """Config should use defaults for missing keys."""
        data = {"upstream": {"mode": "plain"}}
        config = _dict_to_config(data)
        assert config.upstream_mode == "plain"
        assert config.listen_port == 53  # default preserved

    def test_backward_compat_old_upstream(self):
        """Old single-provider config format should be migrated."""
        data = {
            "upstream": {
                "dns": "https://1.1.1.1/dns-query",
                "dot_server": "1.1.1.1",
                "fallback": "1.1.1.1",
                "mode": "doh",
                "timeout": 5.0,
            }
        }
        config = _dict_to_config(data)
        assert len(config.upstream_providers) == 1
        assert config.upstream_providers[0].doh == "https://1.1.1.1/dns-query"
        assert config.upstream_providers[0].plain == "1.1.1.1"

    def test_default_lists_include_all_sources(self):
        config = Config()
        names = {f["name"] for f in config.filter_lists}
        assert "stevenblack-unified" in names
        assert "adguard-dns" in names
        assert "pete-lowe" in names
        assert "malware-domains" in names
        assert "oisd-small" in names
        assert "energized-ultimate" in names
        assert "hagezi-multi-pro" in names
        assert "1hosts-lite" in names
        assert "notracking" in names
        assert "dan-pollock" in names
        assert "phishing-army" in names

    def test_energized_disabled_by_default(self):
        config = Config()
        energized = next(f for f in config.filter_lists if f["name"] == "energized-ultimate")
        assert energized["enabled"] is False

    def test_dashboard_token_default_empty(self):
        config = Config()
        assert config.dashboard_token == ""

    def test_dashboard_token_roundtrip(self):
        config = Config()
        config.dashboard_token = "abc123tokenvalue"
        d = _config_to_dict(config)
        assert d["dashboard"]["token"] == "abc123tokenvalue"
        restored = _dict_to_config(d)
        assert restored.dashboard_token == "abc123tokenvalue"

    def test_dashboard_token_missing_in_dict(self):
        """Token should default to empty if not in config dict."""
        data = {"dashboard": {"enabled": True, "port": 9090}}
        config = _dict_to_config(data)
        assert config.dashboard_token == ""
        assert config.dashboard_port == 9090

    def test_schedule_roundtrip(self):
        config = Config()
        config.schedules = [
            Schedule(
                name="work-hours",
                start="09:00",
                end="17:00",
                days=["mon", "tue", "wed", "thu", "fri"],
                block_domains=["reddit.com"],
                block_patterns=["*.tiktok.com"],
                enabled=True,
            ),
        ]
        d = _config_to_dict(config)
        assert len(d["schedules"]) == 1
        assert d["schedules"][0]["name"] == "work-hours"

        restored = _dict_to_config(d)
        assert len(restored.schedules) == 1
        s = restored.schedules[0]
        assert s.name == "work-hours"
        assert s.start == "09:00"
        assert s.end == "17:00"
        assert s.days == ["mon", "tue", "wed", "thu", "fri"]
        assert s.block_domains == ["reddit.com"]
        assert s.block_patterns == ["*.tiktok.com"]
        assert s.enabled is True

    def test_schedules_default_empty(self):
        config = Config()
        assert config.schedules == []

    def test_parental_config_roundtrip(self):
        config = Config()
        config.safe_search_enabled = True
        config.safe_search_youtube_restrict = "strict"
        config.content_categories = ["adult", "gambling"]

        d = _config_to_dict(config)
        assert d["parental"]["safe_search_enabled"] is True
        assert d["parental"]["safe_search_youtube_restrict"] == "strict"
        assert d["parental"]["content_categories"] == ["adult", "gambling"]

        restored = _dict_to_config(d)
        assert restored.safe_search_enabled is True
        assert restored.safe_search_youtube_restrict == "strict"
        assert restored.content_categories == ["adult", "gambling"]

    def test_parental_defaults(self):
        config = Config()
        assert config.safe_search_enabled is False
        assert config.safe_search_youtube_restrict == "moderate"
        assert config.content_categories == []

    def test_parental_absent_uses_defaults(self):
        """Missing parental section should use defaults."""
        data = {"upstream": {"mode": "doh"}}
        config = _dict_to_config(data)
        assert config.safe_search_enabled is False
        assert config.safe_search_youtube_restrict == "moderate"
        assert config.content_categories == []
