#!/usr/bin/env python3
"""
nav_integration_workbench.py

CLI-verktøy for NAV-integrasjoner:
- Token-håndtering (Maskinporten via JWT-grant).
- Smoke-tester mot NAV-API-er.
- Enkle scenariokjøringer basert på JSON-definerte steg.

Bruk:
    pip install -r requirements.txt

    python nav_integration_workbench.py token --env dev --config nav_workbench.config.json
    python nav_integration_workbench.py smoke --env dev --config nav_workbench.config.json --api nav-test-api
    python nav_integration_workbench.py scenario --env dev --config nav_workbench.config.json --file scenario.example.json
"""

import argparse
import json
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import jwt  # PyJWT
import requests


@dataclass
class MaskinportenConfig:
    client_id: str
    issuer: str
    token_endpoint: str
    audience: str
    scopes: List[str]
    private_key_path: str
    key_id: Optional[str]


@dataclass
class ApiConfig:
    name: str
    base_url: str
    health_path: Optional[str]


@dataclass
class EnvironmentConfig:
    name: str
    maskinporten: MaskinportenConfig
    apis: Dict[str, ApiConfig]
    default_api: Optional[str]


@dataclass
class WorkbenchConfig:
    default_env: str
    environments: Dict[str, EnvironmentConfig]


def load_json(path: Path) -> Any:
    if not path.is_file():
        raise FileNotFoundError(f"Fant ikke fil: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_config(path: Path) -> WorkbenchConfig:
    raw = load_json(path)
    default_env = raw.get("default_env")
    envs_raw = raw.get("environments")
    if not isinstance(envs_raw, dict) or not envs_raw:
        raise ValueError("Config må inneholde 'environments' som ikke-tom objekt")

    environments: Dict[str, EnvironmentConfig] = {}
    for env_name, env_val in envs_raw.items():
        mp_raw = env_val.get("maskinporten") or {}
        mp = MaskinportenConfig(
            client_id=str(mp_raw.get("client_id", "")).strip(),
            issuer=str(mp_raw.get("issuer", "")).strip(),
            token_endpoint=str(mp_raw.get("token_endpoint", "")).strip(),
            audience=str(mp_raw.get("audience", "")).strip(),
            scopes=[str(s).strip() for s in (mp_raw.get("scopes") or [])],
            private_key_path=str(mp_raw.get("private_key_path", "")).strip(),
            key_id=str(mp_raw["key_id"]).strip() if mp_raw.get("key_id") is not None else None,
        )
        apis_raw = env_val.get("apis") or {}
        if not isinstance(apis_raw, dict) or not apis_raw:
            raise ValueError(f"Miljø '{env_name}' mangler 'apis' eller er tomt")
        apis: Dict[str, ApiConfig] = {}
        for api_name, api_val in apis_raw.items():
            base_url = str(api_val.get("base_url", "")).rstrip("/")
            if not base_url:
                raise ValueError(f"API '{api_name}' i miljø '{env_name}' mangler 'base_url'")
            health_path = api_val.get("health_path")
            apis[api_name] = ApiConfig(
                name=api_name,
                base_url=base_url,
                health_path=str(health_path) if health_path is not None else None,
            )
        default_api = env_val.get("default_api")
        environments[env_name] = EnvironmentConfig(
            name=env_name,
            maskinporten=mp,
            apis=apis,
            default_api=str(default_api) if default_api is not None else None,
        )

    if not default_env:
        default_env = next(iter(environments.keys()))

    return WorkbenchConfig(default_env=default_env, environments=environments)


def load_private_key(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"Fant ikke privat nøkkel-fil: {path}")
    return path.read_text(encoding="utf-8")


def build_client_assertion(mp: MaskinportenConfig) -> str:
    now = int(time.time())
    payload = {
        "iss": mp.issuer or mp.client_id,
        "sub": mp.client_id,
        "aud": mp.audience or mp.token_endpoint,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    headers: Dict[str, Any] = {
        "alg": "RS256",
        "typ": "JWT",
    }
    if mp.key_id:
        headers["kid"] = mp.key_id

    private_key = load_private_key(Path(mp.private_key_path))
    assertion = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers=headers,
    )
    if isinstance(assertion, bytes):
        assertion = assertion.decode("utf-8")
    return assertion


def request_maskinporten_token(mp: MaskinportenConfig, extra_scopes: Optional[List[str]] = None) -> Dict[str, Any]:
    assertion = build_client_assertion(mp)
    scopes = mp.scopes[:]
    if extra_scopes:
        for s in extra_scopes:
            if s not in scopes:
                scopes.append(s)
    scope_str = " ".join(scopes)

    data = {
        "grant_type": "client_credentials",
        "scope": scope_str,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }

    resp = requests.post(mp.token_endpoint, data=data, timeout=15)
    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        raise RuntimeError(f"Token-endepunkt feilet ({resp.status_code}): {resp.text}") from e

    token_data = resp.json()
    if "access_token" not in token_data:
        raise RuntimeError(f"Mangler 'access_token' i respons: {token_data}")
    return token_data


def cmd_token(args: argparse.Namespace) -> int:
    cfg = parse_config(Path(args.config))
    env_name = args.env or cfg.default_env
    env = cfg.environments.get(env_name)
    if env is None:
        print(f"Ukjent miljø: {env_name}", file=sys.stderr)
        return 1

    extra_scopes = args.scope or []
    try:
        token_data = request_maskinporten_token(env.maskinporten, extra_scopes=extra_scopes)
    except Exception as e:
        print(f"Feil ved henting av token: {e}", file=sys.stderr)
        return 1

    access_token = token_data.get("access_token")
    expires_in = token_data.get("expires_in")
    scope = token_data.get("scope")
    token_type = token_data.get("token_type")

    print("Token hentet OK:")
    print(f"  token_type: {token_type}")
    print(f"  expires_in: {expires_in}")
    print(f"  scope:      {scope}")
    if args.output:
        out_path = Path(args.output)
        out_path.write_text(access_token, encoding="utf-8")
        print(f"Access token skrevet til {out_path}")
    else:
        print("Access token:")
        print(access_token)

    return 0


def get_bearer_token(cfg: WorkbenchConfig, env_name: Optional[str]) -> Tuple[EnvironmentConfig, str]:
    env_name = env_name or cfg.default_env
    env = cfg.environments.get(env_name)
    if env is None:
        raise ValueError(f"Ukjent miljø: {env_name}")
    token_data = request_maskinporten_token(env.maskinporten)
    access_token = str(token_data["access_token"])
    return env, access_token


def cmd_smoke(args: argparse.Namespace) -> int:
    cfg = parse_config(Path(args.config))
    try:
        env, token = get_bearer_token(cfg, args.env)
    except Exception as e:
        print(f"Feil ved token-henting: {e}", file=sys.stderr)
        return 1

    api_name = args.api or env.default_api
    if not api_name:
        print("Ingen API-navn angitt, og default_api ikke satt i config.", file=sys.stderr)
        return 1

    api = env.apis.get(api_name)
    if api is None:
        print(f"Ukjent API '{api_name}' i miljø '{env.name}'", file=sys.stderr)
        return 1

    if not api.health_path:
        print(f"API '{api_name}' har ikke definert 'health_path' i config.", file=sys.stderr)
        return 1

    url = api.base_url.rstrip("/") + "/" + api.health_path.lstrip("/")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    start = time.perf_counter()
    try:
        resp = requests.get(url, headers=headers, timeout=10)
    except Exception as e:
        print(f"[FAIL] Smoke mot {api_name} feilet med exception: {e}", file=sys.stderr)
        return 1
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    print(f"Smoke-test mot {api_name}:")
    print(f"  URL:        {url}")
    print(f"  Status:     {resp.status_code}")
    print(f"  Responstid: {elapsed_ms:.2f} ms")

    if resp.status_code != 200:
        print(f"[FAIL] Forventet status 200, fikk {resp.status_code}", file=sys.stderr)
        return 1

    print("[OK] Smoke-test bestått.")
    return 0


def cmd_scenario(args: argparse.Namespace) -> int:
    cfg = parse_config(Path(args.config))
    try:
        env, token = get_bearer_token(cfg, args.env)
    except Exception as e:
        print(f"Feil ved token-henting: {e}", file=sys.stderr)
        return 1

    scenario_path = Path(args.file)
    scenario = load_json(scenario_path)

    name = scenario.get("name", scenario_path.stem)
    steps = scenario.get("steps")
    if not isinstance(steps, list) or not steps:
        print("Scenario mangler 'steps' eller listen er tom.", file=sys.stderr)
        return 1

    print(f"Kjører scenario: {name}")
    all_ok = True

    for idx, step in enumerate(steps, start=1):
        api_name = step.get("api") or env.default_api
        method = str(step.get("method", "GET")).upper()
        path = str(step.get("path", "/"))
        expected_status = int(step.get("expected_status", 200))

        if not api_name:
            print(f"[STEP {idx}] Mangler api-navn, og default_api er ikke satt.", file=sys.stderr)
            all_ok = False
            continue

        api = env.apis.get(api_name)
        if api is None:
            print(f"[STEP {idx}] Ukjent API '{api_name}' i miljø '{env.name}'", file=sys.stderr)
            all_ok = False
            continue

        url = api.base_url.rstrip("/") + "/" + path.lstrip("/")
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        print(f"[STEP {idx}] {method} {url} (forventet status {expected_status})")
        start = time.perf_counter()
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, timeout=20)
            elif method == "POST":
                body = step.get("body")
                resp = requests.post(url, headers=headers, json=body, timeout=20)
            elif method == "PUT":
                body = step.get("body")
                resp = requests.put(url, headers=headers, json=body, timeout=20)
            elif method == "DELETE":
                resp = requests.delete(url, headers=headers, timeout=20)
            else:
                print(f"[STEP {idx}] Ustøttet metode: {method}", file=sys.stderr)
                all_ok = False
                continue
        except Exception as e:
            print(f"[STEP {idx}] Exception ved kall: {e}", file=sys.stderr)
            all_ok = False
            continue
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        print(f"  -> status {resp.status_code}, {elapsed_ms:.2f} ms")
        if resp.status_code != expected_status:
            print(
                f"  [FAIL] Forventet {expected_status}, fikk {resp.status_code}. "
                f"Body: {resp.text[:500]}",
                file=sys.stderr,
            )
            all_ok = False
        else:
            print("  [OK] Status som forventet.")

    if not all_ok:
        print("Scenario ferdig med feil.", file=sys.stderr)
        return 1

    print("Scenario ferdig uten feil.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NAV Integration Workbench – token, smoke og scenario-CLI."
    )
    parser.add_argument(
        "--config",
        default="nav_workbench.config.json",
        help="Sti til konfig-fil (JSON). Default nav_workbench.config.json.",
    )
    parser.add_argument(
        "--env",
        help="Miljønavn som brukes (overstyrer default_env i config).",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # token
    p_token = sub.add_parser("token", help="Hent Maskinporten access token.")
    p_token.add_argument(
        "--scope",
        action="append",
        help="Ekstra scope å legge til (kan angis flere ganger).",
    )
    p_token.add_argument(
        "--output",
        help="Valgfri sti for å skrive access token til fil.",
    )
    p_token.set_defaults(func=cmd_token)

    # smoke
    p_smoke = sub.add_parser("smoke", help="Kjør enkel smoke-test mot API.")
    p_smoke.add_argument(
        "--api",
        help="Navn på API slik det er definert i config (ellers brukes default_api).",
    )
    p_smoke.set_defaults(func=cmd_smoke)

    # scenario
    p_scenario = sub.add_parser("scenario", help="Kjør scenario definert i JSON-fil.")
    p_scenario.add_argument(
        "--file",
        required=True,
        help="Sti til scenario-fil (JSON).",
    )
    p_scenario.set_defaults(func=cmd_scenario)

    return parser


def main(argv: Optional[List[str]] = None) -> None:
    if argv is None:
        argv = sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        raise SystemExit(1)
    exit_code = func(args)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
