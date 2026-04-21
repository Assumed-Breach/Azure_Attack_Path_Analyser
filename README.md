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

The analyser produces remediation-focused findings plus attacker-perspective scenarios. Below are **sanitised examples** based on real output structure, with client identities, tenant names, subscription names, app names, and resource names replaced.

### Attack Path AP-1: Turn a production Terraform app into durable production control, secret persistence, and exposed cluster administration

```text
ATTACK PATH AP-1: Turn a production Terraform app into durable production control, secret persistence, and exposed cluster administration

Breach Premise:         [INFERRED] The attacker has the standing app password for terraform-pipeline-prod.
Attacker Objective:     [INFERRED] Keep durable control over production subscriptions, pipeline secrets, and two production AKS clusters.
Why This Works:         [CONFIRMED] BloodHound validates an Owner path from the pipeline identity into multiple production subscriptions. [CONFIRMED] AzureHound shows the same identity has Key Vault secret Get/List/Set rights. [CONFIRMED] Prowler shows both production AKS clusters expose a public management surface.
Findings Enabling Path: [CONFIRMED] AB-001, AB-005, AB-006, AB-007
Estimated Time:         [INFERRED] Minutes.

Step 1 — Reuse the standing pipeline identity.
[Evidence: CONFIRMED — The application has an active long-lived credential and no clear owner accountability.]

Step 2 — Traverse the validated production Owner path.
[Evidence: CONFIRMED — BloodHound returns owner paths from the pipeline identity into multiple production subscriptions.]

Step 3 — Read or change production pipeline secrets without requiring a private admin network.
[Evidence: CONFIRMED — AzureHound grants Key Vault secret access and the vault has permissive network settings.]

Step 4 — Administer the production AKS clusters through their exposed management plane.
[Evidence: CONFIRMED — BloodHound paths reach the production AKS resources and Prowler flags public cluster access.]

Detection Opportunities:
Step 1: [CONFIRMED] Entra service principal sign-in logs would show app authentication. Detectability: MEDIUM.
Step 3: [UNKNOWN] This is not in the collected data. To verify: review Key Vault diagnostic logs and recent secret operations. Detectability: UNKNOWN.
Step 4: [CONFIRMED] Azure Activity Log and AKS diagnostics should show cluster-management changes. Detectability: MEDIUM.

Analyst Notes:
[CONFIRMED] Persistence achieved: yes, through the standing app credential and reachable production secrets.
[CONFIRMED] Cross-tenant risk: no.
[UNKNOWN] Data gaps: This is not in the collected data. To verify: inspect live AKS access settings, node public IP settings, and current secret inventory.
```

### Attack Path AP-2: Pivot from an externally owned management app into internal service principals, then retain access through app-based persistence

```text
ATTACK PATH AP-2: Pivot from an externally owned management app into internal service principals, then retain access through app-based persistence

Breach Premise:         [INFERRED] The attacker controls an externally owned management application already trusted in the tenant.
Attacker Objective:     [INFERRED] Convert an external foothold into internal-looking persistence inside the target tenant.
Why This Works:         [CONFIRMED] AzureHound shows the external app holds high-impact Microsoft Graph write permissions. [CONFIRMED] BloodHound returns secret-add paths from that app to multiple internal service principals. [CONFIRMED] Tenant defaults still allow member-driven app creation and broad consent patterns.
Findings Enabling Path: [CONFIRMED] AB-002, AB-004
Estimated Time:         [INFERRED] Minutes to hours.

Step 1 — Use the external app’s Graph write permissions to change authentication state on reachable internal service principals.
[Evidence: CONFIRMED — App role assignments grant high-impact Graph roles and BloodHound returns secret-add paths.]

Step 2 — Shift persistence into internally named application identities so disabling the original external app does not fully remove access.
[Evidence: CONFIRMED — BloodHound validates credential-add reach to internal service principals.]

Step 3 — Recreate or supplement the foothold later through normal tenant defaults if any ordinary member user is compromised.
[Evidence: CONFIRMED — Tenant defaults leave member app creation and consent-friendly settings enabled.]

Detection Opportunities:
Step 1: [CONFIRMED] Entra audit logs should record application and service-principal credential changes. Detectability: MEDIUM.
Step 2: [CONFIRMED] Service principal sign-in logs should show new or changed app usage. Detectability: MEDIUM.
Step 3: [UNKNOWN] This is not in the collected data. To verify: review alerting for app registration, enterprise app creation, and consent events by non-admin users. Detectability: UNKNOWN.

Analyst Notes:
[CONFIRMED] Persistence achieved: yes, if internal service-principal credentials are added or replaced.
[CONFIRMED] Cross-tenant risk: yes.
[UNKNOWN] Data gaps: This is not in the collected data. To verify: review recent audit activity and current credentials for each reachable internal service principal.
```

### Attack Path AP-3: Use a vendor member admin account for direct directory takeover and leave behind self-owned footholds

```text
ATTACK PATH AP-3: Use a vendor member admin account for direct directory takeover and leave behind self-owned footholds

Breach Premise:         [INFERRED] The attacker compromises a vendor-operated member account such as vendor.admin@corp.example or vendor.support@tenant.example.
Attacker Objective:     [INFERRED] Gain immediate directory-level administrative control and preserve access after the original vendor account is disabled.
Why This Works:         [CONFIRMED] AzureHound shows enabled Member users from a vendor relationship already hold privileged Entra roles. [CONFIRMED] BloodHound validates direct role edges to those directory roles. [CONFIRMED] Tenant defaults still allow member app creation, group creation, and consent-friendly footholds.
Findings Enabling Path: [CONFIRMED] AB-003, AB-004
Estimated Time:         [INFERRED] Minutes.

Step 1 — Sign in as an enabled vendor member account that already holds privileged directory roles.
[Evidence: CONFIRMED — AzureHound shows the vendor-operated accounts are enabled Member users with privileged role assignments.]

Step 2 — Use those built-in admin roles for immediate tenant control.
[Evidence: CONFIRMED — BloodHound validates direct role edges into high-impact Entra roles.]

Step 3 — Create owned apps, groups, or other secondary footholds so access can survive remediation of the original vendor account.
[Evidence: CONFIRMED — Tenant defaults leave member app and group creation enabled.]

Detection Opportunities:
Step 1: [CONFIRMED] Entra sign-in logs would show vendor account authentication. Detectability: MEDIUM.
Step 2: [CONFIRMED] Entra audit logs should show privileged admin actions and role-backed changes. Detectability: HIGH.
Step 3: [UNKNOWN] This is not in the collected data. To verify: review alerting for nonstandard app registrations, new group creation, and consent events by vendor accounts. Detectability: UNKNOWN.

Analyst Notes:
[CONFIRMED] Persistence achieved: yes, through owned applications or groups created after the initial compromise.
[CONFIRMED] Cross-tenant risk: yes.
[UNKNOWN] Data gaps: This is not in the collected data. To verify: review PIM, MFA, Conditional Access, and approved admin workstation controls for the vendor accounts.
```

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
