from pathlib import Path
import sys

# Sørg for at prosjektroten ligger på sys.path når testen kjører (GitHub Actions)
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nav_integration_workbench import parse_config, WorkbenchConfig  # type: ignore


def test_parse_example_config() -> None:
    cfg = parse_config(ROOT / "nav_workbench.config.example.json")
    assert isinstance(cfg, WorkbenchConfig)

    assert "dev" in cfg.environments
    env = cfg.environments["dev"]

    # Maskinporten og Azure AD skal være definert i eksempelconfigen
    assert env.maskinporten is not None
    assert env.azure_ad is not None

    # Vi skal ha minst ett API definert
    assert "nav-test-api" in env.apis
    api = env.apis["nav-test-api"]
    assert api.base_url.startswith("https://")
