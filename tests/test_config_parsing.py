from pathlib import Path

from nav_integration_workbench import parse_config, WorkbenchConfig


def test_parse_example_config() -> None:
    cfg = parse_config(Path("nav_workbench.config.example.json"))
    assert isinstance(cfg, WorkbenchConfig)
    assert "dev" in cfg.environments
    env = cfg.environments["dev"]

    # Maskinporten og Azure AD er definert i eksempelconfigen
    assert env.maskinporten is not None
    assert env.azure_ad is not None

    # Vi skal ha minst ett API definert
    assert "nav-test-api" in env.apis
    api = env.apis["nav-test-api"]
    assert api.base_url.startswith("https://")
