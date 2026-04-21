# Azure Recon Codex Workspace

Offline Azure/Entra reconnaissance analysis for Codex using:

- AzureHound exports
- Prowler JSON-OCSF reports
- BloodHound CE with the BloodHound MCP server

The core idea is simple: analysts drop collected data into `output/`, start a local BloodHound CE stack, install `bloodhound_mcp` separately, and let Codex drive repeatable analysis through the repo's `AGENTS.md` methodology.

## What This Repo Should Be

This should ship as a **GitHub template workspace**, not just a loose analyst folder.

That means the public repo should provide:

- A safe default repo layout
- A documented local BloodHound CE stack
- A Codex project config example
- A clean `AGENTS.md` that encodes the analysis method
- Helper scripts for ingest and collection

It should **not** ship with live secrets or client data.

## Recommended Product Shape

This repo should stay focused on:

- The analyst workflow
- `AGENTS.md`
- Local helper scripts
- Codex project configuration

`bloodhound_mcp` should be installed as an external dependency.

## Quick Start

### 1. Prerequisites

- Docker with Compose
- Python 3.11+
- `uv`
- Codex CLI

OpenAI documents the current Codex CLI flow as:

- Install Codex CLI with `npm i -g @openai/codex`
- Run `codex`
- Authenticate on first run with a ChatGPT account or an API key

Source:

- Codex CLI setup: https://developers.openai.com/codex/cli

### 2. Clone and prepare the repo

```bash
git clone <your-repo-url>
cd <your-repo-dir>
cp .env.example .env
```

Fill in `.env` with your BloodHound API token, Azure service principal values if you want to run collection, and local stack settings.

### 3. Start BloodHound CE locally

```bash
./bloodhound_up.sh
```

This repo expects a local BloodHound CE stack from `docker-compose.yml`.

### 4. Install the BloodHound MCP dependency

Install `bloodhound_mcp` outside this repo. One straightforward layout is a sibling directory:

```bash
git clone https://github.com/mwnickerson/bloodhound_mcp.git ../bloodhound_mcp
uv --directory ../bloodhound_mcp sync
```

### 5. Configure Codex

Project-scoped Codex config is supported through `.codex/config.toml` for trusted projects.

Source:

- Codex config reference: https://developers.openai.com/codex/config-reference
- Codex MCP configuration: https://developers.openai.com/codex/mcp

Copy the example config:

```bash
cp .codex/config.toml.example .codex/config.toml
```

Then edit `.codex/config.toml` and set `cwd` to the absolute path of your external `bloodhound_mcp` checkout.

The OpenAI Docs MCP setup and `~/.codex/config.toml` / project-scoped `.codex/config.toml` pattern are documented here:

- Docs MCP: https://developers.openai.com/learn/docs-mcp

### 6. Provide analysis input

Place evidence in `output/`:

- AzureHound `.json` or `.zip`
- Prowler `.ocsf.json`

Upload AzureHound exports into BloodHound:

```bash
python3 bloodhound_upload.py
```

`bloodhound_upload.py` will auto-select `.zip` files first, or `.json` files if no zip files are present.

### 7. Run analysis with Codex

Start Codex with the wrapper so the repo `.env` is exported to the MCP server:

```bash
./codex_run.sh
```

Then ask for a scoped analysis, for example:

```text
Map the tenants in output, run the standard sweep, and give me findings.
```

## Recommended Codex Model Defaults

OpenAI currently recommends `gpt-5.4` as the starting point if you're unsure which model to use, and separately documents `gpt-5.3-codex` as a coding-optimized option with `low`, `medium`, `high`, and `xhigh` reasoning settings.

For this workspace:

- Default: `gpt-5.4`
- Heavier repo or scripting work: `gpt-5.3-codex`
- Starting reasoning level: `high`

Sources:

- Models overview: https://developers.openai.com/api/docs/models
- GPT-5.3-Codex model page: https://developers.openai.com/api/docs/models/gpt-5.3-codex
- Code generation guidance: https://developers.openai.com/api/docs/guides/code-generation

## Repo Layout

```text
.
├── AGENTS.md
├── README.md
├── .env.example
├── .codex/
│   └── config.toml.example
├── codex_run.sh
├── docker-compose.yml
├── output/
├── bloodhound_upload.py
├── bloodhound_up.sh
├── azurehound_run.sh
├── prowler_run.sh
└── docs/
    └── RELEASE_PLAN.md
```

## Safe Publishing Checklist

Before the first public push:

1. Remove or rotate every secret currently stored in local `.env`.
2. Do not publish `output/` evidence.
3. Do not publish machine-specific `.codex/config.toml`.
4. Keep `bloodhound_mcp` external to this repo.
5. Add a top-level license for this repo's own code and docs.

## Intended Workflow

This workspace is for **offline analysis and reporting**, not live interaction with Azure or Entra control planes.

The analyst loop is:

1. Collect AzureHound and Prowler data.
2. Load AzureHound into BloodHound CE.
3. Let Codex combine raw files, BloodHound MCP graph traversal, and the repo's analysis instructions.
4. Produce findings and attack-path narratives in a repeatable format.
