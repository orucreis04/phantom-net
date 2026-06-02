# Security Policy

Phantom-Net is a defensive deception and honeypot analysis project. Do not deploy it with real credentials, real customer data, or live secrets in decoy responses.

## Public Repository Safety

- Runtime data in `data/` is ignored and must not be committed.
- `.env` and `config.production.yaml` are ignored and must stay private.
- Use `config.production.example.yaml` only as a template.
- Replace all default development credentials before exposing any service.
- Run `python3 main.py --check-config --strict-config` before deployment.

## Default Development Credentials

The default `admin / phantom-admin` credentials are for local development only. They are intentionally documented so a fresh local demo can be opened quickly. They must not be used on an internet-facing host.

## Reporting

If you find a security issue in this repository, contact the maintainer privately before publishing details.
