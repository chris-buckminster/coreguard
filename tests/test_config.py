from coreguard.config import Config, _config_to_dict, _dict_to_config, load_config, save_config


class TestConfig:
    def test_defaults(self):
        config = Config()
        assert config.upstream_mode == "doh"
        assert config.listen_port == 53
        assert config.listen_address == "127.0.0.1"
        assert config.update_interval_hours == 24
        assert len(config.filter_lists) > 0

    def test_roundtrip(self):
        config = Config()
        d = _config_to_dict(config)
        restored = _dict_to_config(d)
        assert restored.upstream_dns == config.upstream_dns
        assert restored.upstream_mode == config.upstream_mode
        assert restored.listen_port == config.listen_port
        assert len(restored.filter_lists) == len(config.filter_lists)

    def test_partial_config(self):
        """Config should use defaults for missing keys."""
        data = {"upstream": {"mode": "plain"}}
        config = _dict_to_config(data)
        assert config.upstream_mode == "plain"
        assert config.listen_port == 53  # default preserved

    def test_default_lists_include_all_sources(self):
        config = Config()
        names = {f["name"] for f in config.filter_lists}
        assert "stevenblack-unified" in names
        assert "adguard-dns" in names
        assert "pete-lowe" in names
        assert "malware-domains" in names
        assert "oisd-small" in names
        assert "energized-ultimate" in names

    def test_energized_disabled_by_default(self):
        config = Config()
        energized = next(f for f in config.filter_lists if f["name"] == "energized-ultimate")
        assert energized["enabled"] is False
