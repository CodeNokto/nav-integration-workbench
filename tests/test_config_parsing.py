from pathlib import Path
import importlib.util
import types

# Prosjektrot og modulsti
ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "nav_integration_workbench.py"


def _load_module() -> types.ModuleType:
    if not MODULE_PATH.is_file():
        raise FileNotFoundError(f"Fant ikke nav_integration_workbench.py på {MODULE_PATH}")
    spec = importlib.util.spec_from_file_location("nav_integration_workbench", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("Kunne ikke lage import-spec for nav_integration_workbench")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_parse_example_config() -> None:
    module = _load_module()
    parse_config = module.parse_config  # type: ignore[attr-defined]
    WorkbenchConfig = module.WorkbenchConfig  # type: ignore[attr-defined]

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
