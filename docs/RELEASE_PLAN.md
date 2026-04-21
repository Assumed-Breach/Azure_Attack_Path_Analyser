# Release Plan

## Recommended Positioning

Publish this as a **Codex-first Azure/Entra recon analysis workspace** for authorised assessments.

The value is not just the helper scripts. The value is the combination of:

- A strong `AGENTS.md` methodology
- BloodHound graph access through MCP
- Offline AzureHound and Prowler evidence handling
- Repeatable analyst output formats

## Best Packaging Decision

Recommendation: ship a **template repo** first, not a standalone web app.

Why:

- The work is analyst-driven, not end-user self-service.
- Codex already provides the agent runtime.
- The repo's differentiator is workflow, context, and structure.
- A template is easier to audit, fork, and adapt for client work.

## Immediate Release Blockers

### 1. Secrets

Do not commit real values in `.env`. Publish only `.env.example`.

### 2. Client data

`output/` should contain only `.gitkeep` in the public repository. Assessment material should stay local.

### 3. Vendored third-party repository

`bloodhound_mcp` should not be published inside this repo. Keep it external and document installation instead.

### 4. Licensing

The external `bloodhound_mcp` project remains under its own license. This repo can choose its own license as long as it does not vendor GPL-covered code into the distributed repository.

## Recommended Public v1

### Included

- `AGENTS.md`
- `README.md`
- `docker-compose.yml`
- `.env.example`
- `.codex/config.toml.example`
- `codex_run.sh`
- Helper scripts for stack startup, upload, and optional collection

### Excluded

- `.env`
- `output/`
- local `.codex/config.toml`
- vendored `bloodhound_mcp`
- any assessment-specific notes, screenshots, or data

## Recommended Analyst Setup

1. Clone the repo.
2. Copy `.env.example` to `.env`.
3. Start the local BloodHound CE stack.
4. Install and configure the external BloodHound MCP server.
5. Add the OpenAI Docs MCP server to Codex.
6. Drop AzureHound and Prowler outputs into `output/`.
7. Run Codex from the repo root and use the included `AGENTS.md`.

## Roadmap

### v1

- Safe repo template
- Clear README
- Local stack helpers
- Codex config example

### v1.1

- Parsing helpers for Prowler HTML and AzureHound file mapping
- Report generation helpers
- Example prompts and analysis tasks

### v2

- Optional packaged installer
- Optional report export automation
- Optional CI checks for repo hygiene and secret scanning
