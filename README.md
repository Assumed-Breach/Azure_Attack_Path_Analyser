# Azure Attack Path Analyser

Turn **AzureHound**, **Prowler**, and **BloodHound** data into evidence-backed Azure / Entra attack paths with **Codex**.

Produce tenant takeover scenarios, privilege-escalation paths, and remediation-ready findings from static cloud recon data.

This repo is built for authorised security assessments and assumed-breach analysis. It takes static cloud recon data and produces:

- validated privilege-escalation paths
- tenant and subscription takeover scenarios
- high-signal findings tied to real identities, roles, apps, and resources
- remediation-ready output grounded in AzureHound records, Prowler findings, BloodHound graph paths, and Microsoft documentation

It works in two stages:

- **Collection**: optional helper scripts run AzureHound and Prowler against an authorised tenant using your supplied credentials
- **Analysis**: Codex works offline against the collected evidence and BloodHound graph data

The AI does not touch the live Azure tenant or Entra control plane during analysis; it analyses the collected findings, graph data, and report artifacts only.

## Data Sources

The analyser works from:

- AzureHound exports
- Prowler JSON-OCSF reports
- BloodHound CE through `bloodhound_mcp`

## 🚀 Two Modes

### 1. Collect evidence

If you do not already have recon data, the repo can collect it for you:

- `./azurehound_run.sh` runs AzureHound through Docker
- `./prowler_run.sh` runs Prowler and writes JSON-OCSF output to `output/`

This stage uses the Azure credentials you place in `.env`.

### 2. Analyse with Codex

Once the data is collected, Codex uses:

- the AzureHound files in `output/`
- the Prowler JSON-OCSF findings in `output/`
- BloodHound graph queries through `bloodhound_mcp`
- the methodology encoded in [`AGENTS.md`](./AGENTS.md)

This is the stage that produces findings and attack paths. It is offline analysis over collected evidence, not live tenant interaction.

## 🔍 What It Does

- Maps tenant and subscription scope from AzureHound collections
- Correlates AzureHound evidence, Prowler exposure findings, and BloodHound graph paths into a single attack narrative
- Surfaces real privilege-escalation paths, exposed high-value resources, and risky users, groups, apps, and service principals
- Produces repeatable findings and operator-grade attack-path scenarios through [`AGENTS.md`](./AGENTS.md)

## 🧠 Why `AGENTS.md` Matters

`AGENTS.md` is the core of the analyser.

It does not just tell Codex to "look at some files." It encodes the actual analyst workflow:

- how to map tenants and file scope before making claims
- how to use `bloodhound_mcp` to make actual BloodHound graph calls for shortest paths, nested membership expansion, and transitive privilege validation
- how to validate paths with BloodHound graph results instead of guessing
- how to distinguish confirmed evidence from inferred conclusions
- how to correlate AzureHound privilege data with Prowler exposure findings
- how to separate true path creators and path amplifiers from generic hardening noise
- how to emit findings and attack paths in a consistent report format

That matters because it makes the output:

- more consistent across runs
- more defensible for client reporting
- less likely to drift into vague LLM summarisation
- grounded in actual BloodHound graph traversal rather than static-file-only interpretation
- much closer to how a real operator would structure Azure / Entra attack-path analysis

In practice, `AGENTS.md` is what turns Codex from a generic coding assistant into a scoped Azure recon analyst.

## 🧱 Inputs

You can either **bring your own evidence** or **collect it with the included scripts**.

Expected evidence in `output/`:

- AzureHound `.json` or `.zip`
- Prowler `.ocsf.json`

Load AzureHound into BloodHound with:

```bash
python3 bloodhound_upload.py
```

The uploader prefers `.zip` files and falls back to `.json` if no zip archives are present.

## ⚙️ Setup

### 1. Install the toolchain

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

### 2. Clone the workspace

```bash
git clone <your-repo-url>
cd <your-repo-dir>
cp .env.example .env
```

Populate `.env` with:

- BloodHound connection details
- BloodHound API token
- optional Azure collection credentials if you want this repo to run AzureHound or Prowler collection locally

### 3. Boot BloodHound CE

```bash
./bloodhound_up.sh
```

### 4. Collect evidence (optional)

If you want the repo to run collection for you:

```bash
./azurehound_run.sh
./prowler_run.sh
```

AzureHound output and Prowler JSON-OCSF reports will be written to `output/`.

### 5. Add `bloodhound_mcp`

Keep `bloodhound_mcp` outside this repo. The cleanest layout is a sibling checkout:

```bash
git clone https://github.com/mwnickerson/bloodhound_mcp.git ../bloodhound_mcp
uv --directory ../bloodhound_mcp sync
```

### 6. Ingest AzureHound into BloodHound

```bash
python3 bloodhound_upload.py
```

### 7. Point Codex at the MCP server

Create the project Codex config:

```bash
cp .codex/config.toml.example .codex/config.toml
```

Then edit `.codex/config.toml` and set `cwd` to the absolute path of your external `bloodhound_mcp` checkout.

### 8. Run the analyst

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

Breach Premise:         [INFERRED] The attacker has the standing devops app password for Terraform-Pipeline-Production.
Attacker Objective:     [INFERRED] Keep durable control over the target production subscriptions, production pipeline secrets, and the two production decisioning AKS clusters.
Why This Works:         [CONFIRMED] BloodHound validates Terraform-Pipeline-Production -> AZRunsAs -> TERRAFORM-PIPELINE-PRODUCTION -> AZOwns/AZMemberOf -> PRODUCTION OWNERS ROLE -> AZOwner -> Prod-Platform, Prod-Core, Prod-Data, Data-Engineering, Decisioning-Prod-A, and Decisioning-Prod-B. [DOCUMENTED — https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles] Azure Owner can manage all resources and assign Azure RBAC roles. [CONFIRMED] AzureHound shows prod-pipeline-kv has networkAcls {} and grants object 00000000-1111-2222-3333-444444444444 secret Get/List/Set. [DOCUMENTED — https://learn.microsoft.com/en-us/azure/key-vault/general/network-security] Microsoft states a firewall-disabled Key Vault accepts requests from all applications and Azure services, with access then controlled by authentication and vault permissions. [CONFIRMED] Prowler flags aks_clusters_public_access_disabled on aks-decisioning-prod-a and aks-decisioning-prod-b. [DOCUMENTED — https://learn.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges] Microsoft states the AKS API server has a public IP by default unless constrained. [DOCUMENTED — https://learn.microsoft.com/en-us/azure/aks/use-node-public-ips] AKS nodes do not require public IPs for normal communication.
Findings Enabling Path: [CONFIRMED] AB-001, AB-005, AB-006, AB-007
Estimated Time:         [INFERRED] Minutes.

Step 1 — Reuse the standing pipeline identity.
[Evidence: CONFIRMED — AZApp 00000000-aaaa-bbbb-cccc-111111111111 has password credential expiry 2299-12-31T00:00:00Z, and AZAppOwner / AZServicePrincipalOwner are null.]

Step 2 — Traverse the validated production Owner path.
[Evidence: CONFIRMED — BloodHound returns validated owner paths from Terraform-Pipeline-Production into the production subscriptions listed above.]

Step 3 — Read or change production pipeline secrets without needing a private admin network.
[Evidence: CONFIRMED — AzureHound grants Terraform-Pipeline-Production secret Get/List/Set on prod-pipeline-kv; CONFIRMED — the vault record has empty networkAcls; DOCUMENTED — https://learn.microsoft.com/en-us/azure/key-vault/general/network-security]

Step 4 — Administer the two production decisioning AKS clusters through their public management surface once owner-level control is established.
[Evidence: CONFIRMED — BloodHound shortest paths reach AKS-DECISIONING-PROD-A and AKS-DECISIONING-PROD-B; CONFIRMED — Prowler flags public access on both clusters; DOCUMENTED — https://learn.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges]

Detection Opportunities:
Step 1: [CONFIRMED] Entra service principal sign-in logs would show app authentication. Detectability: MEDIUM.
Step 3: [UNKNOWN] This is not in the collected data. To verify: review Key Vault diagnostic logs and recent secret operations for prod-pipeline-kv. Detectability: UNKNOWN.
Step 4: [CONFIRMED] Azure Activity Log and AKS diagnostic logs should show cluster-management changes. Detectability: MEDIUM.

Analyst Notes:
[CONFIRMED] Persistence achieved: yes, via the standing app secret and any production secrets reachable through the vault.
[CONFIRMED] Cross-tenant risk: no.
[INFERRED] Additional Prowler exposure widens blast radius: several production Cosmos DB accounts allow all networks and do not use private endpoints, so any already-authorized workload or stolen database secret would face weaker network containment. [DOCUMENTED — https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-firewall] [DOCUMENTED — https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-private-endpoints]
[UNKNOWN] Data gaps: This is not in the collected data. To verify: inspect live AKS apiServerAccessProfile, node-pool public IP settings, and the current secret inventory in prod-pipeline-kv.
```

### Attack Path AP-2: Pivot from an externally owned management app into internal service principals, then retain access through app-based persistence

```text
ATTACK PATH AP-2: Pivot from an externally owned management app into internal service principals, then retain access through app-based persistence

Breach Premise:         [INFERRED] The attacker controls the external operator behind External-Management-App or its managing tenant.
Attacker Objective:     [INFERRED] Convert an externally owned foothold into internal-looking persistence inside the target tenant.
Why This Works:         [CONFIRMED] AzureHound shows External-Management-App is externally owned by tenant 99999999-8888-7777-6666-555555555555 and holds Application.ReadWrite.All, Group.ReadWrite.All, User.ReadWrite.All, Domain.ReadWrite.All, and Policy.ReadWrite.AuthenticationFlows against Microsoft Graph. [DOCUMENTED — https://learn.microsoft.com/en-us/graph/permissions-reference] Microsoft documents Application.ReadWrite.All as allowing create, read, update, and delete of applications and service principals. [CONFIRMED] BloodHound returns External-Management-App -> AZMGAddSecret -> multiple internal service principals. [CONFIRMED] The same tenant fails the default-member app creation, group creation, and user-consent checks in AB-004. [DOCUMENTED — https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions] Member users can register applications and manage credentials on applications they own. [DOCUMENTED — https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent] Microsoft recommends restricting user consent to reduce malicious app risk.
Findings Enabling Path: [CONFIRMED] AB-002, AB-004
Estimated Time:         [INFERRED] Minutes to hours.

Step 1 — Use the external app’s Graph write permissions to change authentication state on reachable internal service principals.
[Evidence: CONFIRMED — AZAppRoleAssignment grants the high-impact Graph roles; CONFIRMED — BloodHound returns AZMGAddSecret edges from External-Management-App to multiple service principals.]

Step 2 — Shift persistence into internally named application identities so disabling the original external app does not fully remove access.
[Evidence: CONFIRMED — BloodHound validates secret-add reach to internal service principals; INFERRED — once new credentials are added to those internal identities, access no longer depends solely on the original external app.]

Step 3 — Recreate or supplement the foothold later through normal tenant defaults if any ordinary member user is compromised.
[Evidence: CONFIRMED — AB-004 shows default member app creation and user consent remain enabled; DOCUMENTED — https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions; DOCUMENTED — https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent]

Detection Opportunities:
Step 1: [CONFIRMED] Entra audit logs should record application and service-principal credential changes. Detectability: MEDIUM.
Step 2: [CONFIRMED] Service principal sign-in logs should show new or changed app usage. Detectability: MEDIUM.
Step 3: [UNKNOWN] This is not in the collected data. To verify: review alerting for app registration, enterprise app creation, and consent events by non-admin users. Detectability: UNKNOWN.

Analyst Notes:
[CONFIRMED] Persistence achieved: yes, if internal service-principal credentials are added or replaced.
[CONFIRMED] Cross-tenant risk: yes.
[INFERRED] AB-004 does not create the initial external-app path, but it makes eradication harder by leaving redundant app-based persistence patterns available inside the tenant.
[UNKNOWN] Data gaps: This is not in the collected data. To verify: review recent audit activity and current credentials for every service principal returned by the AZMGAddSecret paths.
```

### Attack Path AP-3: Use a vendor member admin account for direct directory takeover and leave behind self-owned footholds

```text
ATTACK PATH AP-3: Use a vendor member admin account for direct directory takeover and leave behind self-owned footholds

Breach Premise:         [INFERRED] The attacker compromises vendor.admin@examplecorp.com or vendor.support@exampletenant.onmicrosoft.com.
Attacker Objective:     [INFERRED] Gain immediate tenant administrative control and preserve access after the original vendor account is disabled.
Why This Works:         [CONFIRMED] AzureHound shows vendor.admin@examplecorp.com is an enabled Member user with Global Administrator, and vendor.support@exampletenant.onmicrosoft.com is an enabled Member user with User Administrator, Cloud Device Administrator, and Intune Administrator. [CONFIRMED] BloodHound validates the direct AZHasRole edges to Global Administrator and User Administrator. [DOCUMENTED — https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference] Those are privileged administrative roles. [CONFIRMED] The tenant also fails the default-member app creation, group creation, Microsoft 365 group creation, and user-consent checks from AB-004. [DOCUMENTED — https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions]
Findings Enabling Path: [CONFIRMED] AB-003, AB-004
Estimated Time:         [INFERRED] Minutes.

Step 1 — Sign in as an enabled vendor member account that already holds privileged directory roles.
[Evidence: CONFIRMED — AzureHound shows both vendor accounts are enabled Member users with the listed role assignments.]

Step 2 — Use the existing privileged directory roles for immediate tenant control.
[Evidence: CONFIRMED — BloodHound validates direct AZHasRole edges into Global Administrator and User Administrator.]

Step 3 — Create owned apps, groups, or other secondary footholds so access can survive remediation of the original vendor account.
[Evidence: CONFIRMED — AB-004 leaves member app and group creation enabled; DOCUMENTED — https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions]

Detection Opportunities:
Step 1: [CONFIRMED] Entra sign-in logs would show vendor account authentication. Detectability: MEDIUM.
Step 2: [CONFIRMED] Entra audit logs should show privileged admin actions and role-backed changes. Detectability: HIGH.
Step 3: [UNKNOWN] This is not in the collected data. To verify: review alerting for nonstandard app registrations, new group creation, and consent events by vendor accounts. Detectability: UNKNOWN.

Analyst Notes:
[CONFIRMED] Persistence achieved: yes, through owned applications or groups created after the initial compromise.
[CONFIRMED] Cross-tenant risk: yes.
[INFERRED] AB-004 materially changes this from “vendor admin account compromise” into “vendor admin compromise with easy secondary footholds.”
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

```
