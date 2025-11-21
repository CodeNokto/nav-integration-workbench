# NAV Integration Workbench

CLI-verktøy for å håndtere tokens, smoke-tester og enkle scenarier mot NAV-API-er.

## Funksjonelt

- Leser en JSON-konfig med miljøer, Maskinporten-oppsett og API-definisjoner.
- Genererer OAuth2 access tokens mot Maskinporten ved hjelp av private key (JWT-grant).
- Kjører enkle smoke-tester mot NAV-API-er (statuskode + svartid).
- Kjøring av scenarier definert i JSON (sekvens av API-kall med forventet status).

Dette repoet er ment som et arbeidsverktøy og et eksempel på hvordan
eksterne integrasjoner kan struktureres rundt NAV sin integrasjonsstack.

## Filstruktur

- `nav_integration_workbench.py` – hoved-CLI-en.
- `nav_workbench.config.example.json` – eksempel på konfig for miljøer, Maskinporten og API-er.
- `scenario.example.json` – eksempel på scenariodefinisjon.
- `requirements.txt` – Python-avhengigheter.
- `.gitignore` – standard Python-ignores.

## Installasjon

```bash
pip install -r requirements.txt
```

## Konfigurasjon

Kopier eksempelkonfigen og fyll inn dine faktiske verdier:

```bash
cp nav_workbench.config.example.json nav_workbench.config.json
```

Editer `nav_workbench.config.json` med riktige:
- klient-ID(er)
- token-endepunkt
- audience/issuer
- sti til privat nøkkel (PEM-fil)
- scopes
- API-base-URL-er

## Bruk

Generer Maskinporten-token:

```bash
python nav_integration_workbench.py token --env dev --config nav_workbench.config.json
```

Kjør smoke-test mot definert API:

```bash
python nav_integration_workbench.py smoke --env dev --config nav_workbench.config.json --api nav-test-api
```

Kjør scenario:

```bash
python nav_integration_workbench.py scenario --env dev --config nav_workbench.config.json --file scenario.example.json
```

Alle kommandoer printer en konsis rapport til stdout og returnerer exit-koder
som egner seg for CI/CD (0 ved suksess, 1 ved feil).
