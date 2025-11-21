#!/usr/bin/env python3
"""
NAV Integration Workbench

CLI-verktøy for NAV-integrasjoner:
- Token-håndtering (Maskinporten og Azure AD).
- Smoke-tester mot API-er.
- Enkle scenariokjøringer basert på JSON-definerte steg.
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
class AzureAdConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    token_endpoint: str
    scopes: List[str]


@dataclass
class ApiConfig:
    name: str
    base_url: str
    health_path: Optional[str]


@dataclass
class EnvironmentConfig:
    name: str
    auth_type: str
    maskinporten: Optional[MaskinportenConfig]
    azure_ad: Optional[AzureAdConfig]
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
        raise ValueError("Config må inneholde 'environments' som ikke-tomt objekt")

    environments: Dict[str, EnvironmentConfig] = {}
    for env_name, env_val in envs_raw.items():
        auth_type = str(env_val.get("auth_type", "maskinporten")).lower()

        mp_raw = env_val.get("maskinporten") or {}
        mp_cfg: Optional[MaskinportenConfig] = None
        if mp_raw:
            mp_cfg = MaskinportenConfig(
                client_id=str(mp_raw.get("client_id", "")).strip(),
                issuer=str(mp_raw.get("issuer", "")).strip(),
                token_endpoint=str(mp_raw.get("token_endpoint", "")).strip(),
                audience=str(mp_raw.get("audience", "")).strip(),
                scopes=[str(s).strip() for s in (mp_raw.get("scopes") or [])],
                private_key_path=str(mp_raw.get("private_key_path", "")).strip(),
                key_id=str(mp_raw["key_id"]).strip() if mp_raw.get("key_id") is not None else None,
            )

        az_raw = env_val.get("azure_ad") or {}
        az_cfg: Optional[AzureAdConfig] = None
        if az_raw:
            az_cfg = AzureAdConfig(
                tenant_id=str(az_raw.get("tenant_id", "")).strip(),
                client_id=str(az_raw.get("client_id", "")).strip(),
                client_secret=str(az_raw.get("client_secret", "")).strip(),
                token_endpoint=str(az_raw.get("token_endpoint", "")).strip(),
                scopes=[str(s).strip() for s in (az_raw.get("scopes") or [])],
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
            auth_type=auth_type,
            maskinporten=mp_cfg,
            azure_ad=az_cfg,
            apis=apis,
            default_api=str(default_api) if default_api is not None else None,
        )

    if not default_env:
        default_env = next(iter(environments.keys()))

    return WorkbenchConfig(default_env=str(default_env), environments=environments)


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
    if not mp.client_id or not mp.token_endpoint:
        raise ValueError("Maskinporten-config mangler client_id eller token_endpoint")

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
        raise RuntimeError(f"Maskinporten token-endepunkt feilet ({resp.status_code}): {resp.text}") from e

    token_data = resp.json()
    if "access_token" not in token_data:
        raise RuntimeError(f"Mangler 'access_token' i Maskinporten-respons: {token_data}")
    return token_data


def request_azure_token(az: AzureAdConfig, extra_scopes: Optional[List[str]] = None) -> Dict[str, Any]:
    if not az.client_id or not az.client_secret or not az.token_endpoint:
        raise ValueError("Azure AD-config mangler client_id, client_secret eller token_endpoint")

    scopes = az.scopes[:]
    if extra_scopes:
        for s in extra_scopes:
            if s not in scopes:
                scopes.append(s)
    scope_str = " ".join(scopes)

    data = {
        "grant_type": "client_credentials",
        "client_id": az.client_id,
        "client_secret": az.client_secret,
        "scope": scope_str,
    }

    resp = requests.post(az.token_endpoint, data=data, timeout=15)
    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        raise RuntimeError(f"Azure AD token-endepunkt feilet ({resp.status_code}): {resp.text}") from e

    token_data = resp.json()
    if "access_token" not in token_data:
        raise RuntimeError(f"Mangler 'access_token' i Azure-respons: {token_data}")
    return token_data


def get_env_and_token(
    cfg: WorkbenchConfig,
    env_name: Optional[str],
    auth_override: Optional[str],
    extra_scopes: Optional[List[str]] = None,
) -> Tuple[EnvironmentConfig, str]:
    env_name = env_name or cfg.default_env
    env = cfg.environments.get(env_name)
    if env is None:
        raise ValueError(f"Ukjent miljø: {env_name}")

    auth_type = (auth_override or env.auth_type).lower()
    if auth_type == "maskinporten":
        if env.maskinporten is None:
            raise ValueError(f"Miljø '{env.name}' mangler maskinporten-config")
        token_data = request_maskinporten_token(env.maskinporten, extra_scopes=extra_scopes)
    elif auth_type in ("azure", "azure_ad", "aad"):
        if env.azure_ad is None:
            raise ValueError(f"Miljø '{env.name}' mangler azure_ad-config")
        token_data = request_azure_token(env.azure_ad, extra_scopes=extra_scopes)
    else:
        raise ValueError(f"Ukjent auth_type: {auth_type}")

    access_token = str(token_data["access_token"])
    return env, access_token


def cmd_token(args: argparse.Namespace) -> int:
    cfg = parse_config(Path(args.config))
    extra_scopes = args.scope or []

    try:
        env, _ = get_env_and_token(cfg, args.env, args.auth, extra_scopes=extra_scopes)
        # get_env_and_token returnerer token, men vi trenger også token_data-detaljer
        auth_type = (args.auth or env.auth_type).lower()
        if auth_type == "maskinporten":
            if env.maskinporten is None:
                raise ValueError("Maskinporten-config mangler")
            token_data = request_maskinporten_token(env.maskinporten, extra_scopes=extra_scopes)
        else:
            if env.azure_ad is None:
                raise ValueError("Azure AD-config mangler")
            token_data = request_azure_token(env.azure_ad, extra_scopes=extra_scopes)
    except Exception as e:
        print(f"Feil ved henting av token: {e}", file=sys.stderr)
        return 1

    access_token = token_data.get("access_token")
    expires_in = token_data.get("expires_in")
    scope = token_data.get("scope")
    token_type = token_data.get("token_type")

    print("Token hentet OK:")
    print(f"  auth_type:  {(args.auth or env.auth_type)}")
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


def cmd_smoke(args: argparse.Namespace) -> int:
    cfg = parse_config(Path(args.config))
    try:
        env, token = get_env_and_token(cfg, args.env, args.auth)
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
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        print(f"[FAIL] Smoke mot {api_name} feilet med exception: {e}", file=sys.stderr)
        result = {
            "env": env.name,
            "api": api.name,
            "url": url,
            "status_code": None,
            "expected_status": 200,
            "response_ms": elapsed_ms,
            "ok": False,
            "error": str(e),
        }
        if args.output:
            _write_smoke_report(Path(args.output), result)
        return 1
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    ok_status = resp.status_code == 200
    result = {
        "env": env.name,
        "api": api.name,
        "url": url,
        "status_code": resp.status_code,
        "expected_status": 200,
        "response_ms": elapsed_ms,
        "ok": ok_status,
    }

    print(f"Smoke-test mot {api_name}:")
    print(f"  URL:        {url}")
    print(f"  Status:     {resp.status_code}")
    print(f"  Responstid: {elapsed_ms:.2f} ms")

    if ok_status:
        print("[OK] Smoke-test bestått.")
    else:
        print(f"[FAIL] Forventet status 200, fikk {resp.status_code}", file=sys.stderr)

    if args.output:
        _write_smoke_report(Path(args.output), result)

    return 0 if ok_status else 1


def _write_smoke_report(path: Path, result: Dict[str, Any]) -> None:
    report = {
        "summary": {
            "env": result["env"],
            "api": result["api"],
            "total": 1,
            "passed": 1 if result["ok"] else 0,
            "failed": 0 if result["ok"] else 1,
        },
        "result": result,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"Rapport skrevet til {path}")


def cmd_scenario(args: argparse.Namespace) -> int:
    cfg = parse_config(Path(args.config))
    try:
        env, token = get_env_and_token(cfg, args.env, args.auth)
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
    results: List[Dict[str, Any]] = []

    for idx, step in enumerate(steps, start=1):
        api_name = step.get("api") or env.default_api
        method = str(step.get("method", "GET")).upper()
        path_val = str(step.get("path", "/"))
        expected_status = int(step.get("expected_status", 200))
        body = step.get("body")

        if not api_name:
            print(f"[STEP {idx}] Mangler api-navn, og default_api er ikke satt.", file=sys.stderr)
            all_ok = False
            continue

        api = env.apis.get(api_name)
        if api is None:
            print(f"[STEP {idx}] Ukjent API '{api_name}' i miljø '{env.name}'", file=sys.stderr)
            all_ok = False
            continue

        url = api.base_url.rstrip("/") + "/" + path_val.lstrip("/")
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
                resp = requests.post(url, headers=headers, json=body, timeout=20)
            elif method == "PUT":
                resp = requests.put(url, headers=headers, json=body, timeout=20)
            elif method == "DELETE":
                resp = requests.delete(url, headers=headers, timeout=20)
            else:
                print(f"[STEP {idx}] Ustøttet metode: {method}", file=sys.stderr)
                all_ok = False
                continue
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            print(f"[STEP {idx}] Exception ved kall: {e}", file=sys.stderr)
            all_ok = False
            results.append(
                {
                    "step": idx,
                    "api": api_name,
                    "method": method,
                    "url": url,
                    "status_code": None,
                    "expected_status": expected_status,
                    "response_ms": elapsed_ms,
                    "ok": False,
                    "error": str(e),
                }
            )
            continue
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        ok_status = resp.status_code == expected_status
        ok = ok_status
        if ok:
            print("  [OK] Status som forventet.")
        else:
            print(
                f"  [FAIL] Forventet {expected_status}, fikk {resp.status_code}. "
                f"Body: {resp.text[:500]}",
                file=sys.stderr,
            )
        results.append(
            {
                "step": idx,
                "api": api_name,
                "method": method,
                "url": url,
                "status_code": resp.status_code,
                "expected_status": expected_status,
                "response_ms": elapsed_ms,
                "ok": ok,
            }
        )
        all_ok = all_ok and ok

    summary = {
        "env": env.name,
        "scenario": name,
        "total": len(results),
        "passed": sum(1 for r in results if r["ok"]),
        "failed": sum(1 for r in results if not r["ok"]),
    }

    print("Scenario oppsummert:")
    print(f"  total:  {summary['total']}")
    print(f"  passed: {summary['passed']}")
    print(f"  failed: {summary['failed']}")

    if args.output:
        report = {"summary": summary, "results": results}
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"Scenario-rapport skrevet til {out_path}")

    return 0 if all_ok else 1


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
    parser.add_argument(
        "--auth",
        choices=["maskinporten", "azure_ad"],
        help="Overstyr auth-type for miljøet (maskinporten eller azure_ad).",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # token
    p_token = sub.add_parser("token", help="Hent access token.")
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
    p_smoke.add_argument(
        "--output",
        help="Valgfri sti for å skrive JSON-rapport.",
    )
    p_smoke.set_defaults(func=cmd_smoke)

    # scenario
    p_scenario = sub.add_parser("scenario", help="Kjør scenario definert i JSON-fil.")
    p_scenario.add_argument(
        "--file",
        required=True,
        help="Sti til scenario-fil (JSON).",
    )
    p_scenario.add_argument(
        "--output",
        help="Valgfri sti for å skrive JSON-rapport.",
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
