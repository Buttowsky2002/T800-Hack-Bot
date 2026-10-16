# T800-Hack-Bot

AI-driven engagement-centric pentest bot for solo security engineers.

## Quick start

1. Copy `pentest_bot_t800/config/config.example.yaml` → `config.yaml`
2. Export `ANTHROPIC_API_KEY` (never put keys in YAML)
3. Optional: copy `.pentest_vault.example.yaml` → `.pentest_vault.yaml` for persona tokens
4. Run: `python -m pentest_bot_t800 interactive`

## Engagement workflow

```
engage new studio https://app.example.com
engage openapi ./openapi.json
engage har ./capture.har
engage cloud aws
agentic          # coverage-guided technique loop
authz            # multi-persona BOLA/IDOR
cloud aws        # prowler + web correlation
coverage
retest <finding_id>
```

Findings are triaged → verified → ticket packages under `runs/<id>/tickets/`.
Only **confirmed** findings appear in the executive report.

The T-800 Hack Bot automates and enhances the full penetration testing lifecycle with technique-based planning (ASVS L2 + CIS coverage), authenticated scanning, and actionable ticket output.
