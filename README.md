# Azure Attack Path Analyser

Offline Azure / Entra attack-path analysis for **Codex** using:

- AzureHound exports
- Prowler JSON-OCSF reports
- BloodHound CE through `bloodhound_mcp`

This repo is designed for **authorised security assessments**. It helps analysts turn static cloud recon data into structured findings and attacker-focused scenarios without querying live Azure or Entra control planes.

## 🔍 What It Does

- Maps tenants and subscriptions from AzureHound data
- Correlates AzureHound, Prowler, and BloodHound graph results
- Identifies privilege paths, exposed high-value resources, and risky service principals
- Produces repeatable findings and attack-path narratives through [`AGENTS.md`](./AGENTS.md)

## 🧱 Inputs

Place evidence in `output/`:

- AzureHound `.json` or `.zip`
- Prowler `.ocsf.json`

Upload AzureHound exports into BloodHound:

```bash
python3 bloodhound_upload.py
```

`bloodhound_upload.py` selects `.zip` files first, or `.json` files if no zip files are present.

## ⚙️ Setup

### 1. Prerequisites

- Docker with Compose
- Python 3.11+
- `uv`
- Codex CLI

Install Codex CLI:

```bash
npm i -g @openai/codex
```

OpenAI docs:

- Codex CLI: https://developers.openai.com/codex/cli
- Codex config: https://developers.openai.com/codex/config-reference
- Codex MCP: https://developers.openai.com/codex/mcp

### 2. Clone and prepare the repo

```bash
git clone <your-repo-url>
cd <your-repo-dir>
cp .env.example .env
```

Fill in `.env` with your BloodHound connection details, API token, and optional Azure collection credentials.

### 3. Start BloodHound CE

```bash
./bloodhound_up.sh
```

### 4. Install `bloodhound_mcp`

Keep `bloodhound_mcp` outside this repo. A simple layout is a sibling directory:

```bash
git clone https://github.com/mwnickerson/bloodhound_mcp.git ../bloodhound_mcp
uv --directory ../bloodhound_mcp sync
```

### 5. Configure Codex

Copy the example config:

```bash
cp .codex/config.toml.example .codex/config.toml
```

Then edit `.codex/config.toml` and set `cwd` to the absolute path of your external `bloodhound_mcp` checkout.

### 6. Run Codex

Start Codex through the wrapper so the repo `.env` is exported to the MCP server:

```bash
./codex_run.sh
```

Example prompt:

```text
Map the tenants in output, run the standard sweep, and give me findings and attack paths.
```

## 📤 Output

The analyser produces remediation-focused findings plus attacker-perspective scenarios. Below are **sanitised examples** with placeholder identities, tenants, subscriptions, and resources.

### Attack Path AP-1: Low-Privilege User to Tenant-Wide App Control

**Breach Premise:** `user@corp.example` is compromised.  
**Objective:** Gain durable control over application identities in the tenant.

1. The user can register an application because tenant defaults permit member app registration.
2. The created app receives a high-impact Microsoft Graph permission through an exposed admin-consent path or mis-scoped app governance.
3. The attacker adds credentials to a privileged app or creates a new long-lived service principal foothold.

**Impact:** Tenant-wide persistence and delegated privilege escalation.

### Attack Path AP-2: External Service Principal to Production Subscription Control

**Breach Premise:** An externally owned service principal already trusted in the tenant is compromised.  
**Objective:** Take control of a production subscription.

1. The external service principal holds a privileged role on `Production-Subscription-A`.
2. BloodHound confirms control reaches resource groups and production workloads inside that subscription.
3. Prowler findings show weak boundaries on attached high-value resources, increasing blast radius after control is obtained.

**Impact:** Broad resource modification, persistence, and access to production management surfaces.

### Attack Path AP-3: Managed Identity to Sensitive Secret Access

**Breach Premise:** A workload identity on `prod-functionapp-01` is compromised.  
**Objective:** Access secrets used by downstream production services.

1. The Function App managed identity has privileged access on a production resource group or Key Vault.
2. BloodHound confirms the workload identity can reach the target resource through direct or inherited assignments.
3. Prowler shows the target Key Vault or data service has weak network controls, removing a boundary that would otherwise slow or limit abuse.

**Impact:** Secret theft, service impersonation, and follow-on access into production systems.

## 🗂 Repo Layout

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

## Notes

- This repo is for **offline analysis and reporting**, not live Azure or Entra interaction.
- Do not commit `.env`, real assessment data, or local `.codex/config.toml`.
- Keep `bloodhound_mcp` external to this repository.
