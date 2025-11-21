# NAV Integration Workbench

CLI-verktøy for å håndtere tokens, smoke-tester og scenarier mot NAV-API-er.

## Hva verktøyet løser

- Én konsistent måte å hente tokens på (Maskinporten og Azure AD).
- Én kommandolinje for å kjøre smoke-tester mot NAV-API-er.
- Enkelt å definere scenarier som kaller flere API-endepunkter i rekkefølge.
- Exit-koder og JSON-rapporter som kan brukes direkte i CI/CD.

## Funksjoner

- Støtter både Maskinporten (JWT-grant) og Azure AD (client_credentials).
- Miljøer og API-er defineres i en JSON-konfigfil.
- `token`-kommando for å hente og skrive ut tokens.
- `smoke`-kommando for å teste et API (statuskode + responstid) og skrive rapport.
- `scenario`-kommando for å kjøre flere kall i rekkefølge basert på en scenariofil.
- Enkle pytest-tester og GitHub Actions-workflow for å verifisere koden.

## Filstruktur

- `nav_integration_workbench.py` – hoved-CLI.
- `nav_workbench.config.example.json` – eksempelkonfig for miljø, auth og API-er.
- `scenario.example.json` – eksempel på scenario.
- `requirements.txt` – avhengigheter (requests, PyJWT, pytest for test).
- `tests/test_config_parsing.py` – enkel test av konfig-parsing.
- `.github/workflows/ci.yml` – GitHub Actions-workflow.
- `.gitignore` – standard Python + lokale hemmeligheter (config, nøkkel).

## Installasjon lokalt

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
```

## Konfigurasjon

Kopier eksempelkonfigen og fyll inn dine faktiske verdier:

```bash
cp nav_workbench.config.example.json nav_workbench.config.json
```

Viktige felter:

- `default_env` – navn på standardmiljø.
- `environments.<navn>.auth_type` – `maskinporten` eller `azure_ad`.
- `environments.<navn>.maskinporten` – Maskinporten-oppsett for det miljøet.
- `environments.<navn>.azure_ad` – Azure AD-oppsett for det miljøet.
- `environments.<navn>.apis` – liste med API-er (base_url, health_path osv.).

## Eksempelbruk

Hent Maskinporten-token (bruker `auth_type` fra miljøet, eller `--auth`):

```bash
python nav_integration_workbench.py --config nav_workbench.config.json --env dev token
```

Kjør smoke-test mot et API (navn definert i config):

```bash
python nav_integration_workbench.py --config nav_workbench.config.json --env dev smoke --api nav-test-api --output smoke_report.json
```

Kjør scenario:

```bash
python nav_integration_workbench.py --config nav_workbench.config.json --env dev scenario --file scenario.example.json --output scenario_report.json
```

## CI

Repoet inneholder en GitHub Actions-workflow som:

- installerer dependencies,
- kjører pytest,
- kompilerer alle .py-filer med `compileall`.

Dette er nok til å vise at prosjektet er testbart og byggbart uten ekstra oppsett.
Dette er et uoffisielt open source-verktøy laget på eget initiativ for å forenkle arbeid med NAV-API-er.
Prosjektet er ikke bestilt eller driftet av NAV, men kan brukes som støtteverktøy av integrasjonspartnere og utviklere.
