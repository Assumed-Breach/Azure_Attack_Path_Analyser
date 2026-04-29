# Azure/Entra Assessment Report Template

Use this template for operator-facing output. It is intentionally layered: a reader should be able to understand the key risk from the summary sections without reading the full findings or scenarios.

## Executive Summary

- Scope: `<tenant, subscription set, or named analysis scope>`. `[CONFIRMED/INFERRED]`
- Coverage: `<AzureHound files, BloodHound graph state, Prowler availability, major gaps>`. `[CONFIRMED/UNKNOWN]`
- Finding count: `<X CRITICAL, Y HIGH, Z MEDIUM, ...>`. `[CONFIRMED]`
- Top risk 1: `<plain-language statement>`. `[CONFIRMED/INFERRED]`
- Top risk 2: `<plain-language statement>`. `[CONFIRMED/INFERRED]`
- Top risk 3: `<plain-language statement>`. `[CONFIRMED/INFERRED]`

## Finding Summary Table

| ID | Severity | Identity / Resource | Risk Summary |
|----|----------|---------------------|--------------|
| F-001 | CRITICAL | `<identity or resource>` | `<one sentence summary>` |
| F-002 | HIGH | `<identity or resource>` | `<one sentence summary>` |
| F-003 | MEDIUM | `<identity or resource>` | `<one sentence summary>` |

## Detailed Findings

### F-001

ID: `F-001`
Title: `<plain-language title naming the identity and resource>`
Severity: `CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL`
Confidence: `[CONFIRMED/DOCUMENTED/INFERRED/UNKNOWN]`
Summary: `<one sentence: who has what and why it matters>`
Chain: `<Identity> -> <Relationship> -> <Resource> -> <Impact>`
Prowler Ref: `<Check ID or N/A>`
MITRE: `<Tactic: Technique ID — Name>`
Why It Matters: `<2 to 4 lines maximum; explain consequence in operator language>`
Evidence: `<specific AzureHound/BloodHound/Prowler evidence with tags>`
Blast Radius: `<what is reachable if exploited>`
Detection Gap: `<what monitoring is absent or insufficient>`
Validation:
1. `<operator validation step>`
2. `<operator validation step>`
3. `<operator validation step>`
Remediation: `<action> — <Microsoft framework name, section, URL>`

### F-002

ID: `F-002`
Title: `<plain-language title naming the identity and resource>`
Severity: `CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL`
Confidence: `[CONFIRMED/DOCUMENTED/INFERRED/UNKNOWN]`
Summary: `<one sentence: who has what and why it matters>`
Chain: `<Identity> -> <Relationship> -> <Resource> -> <Impact>`
Prowler Ref: `<Check ID or N/A>`
MITRE: `<Tactic: Technique ID — Name>`
Why It Matters: `<2 to 4 lines maximum; explain consequence in operator language>`
Evidence: `<specific AzureHound/BloodHound/Prowler evidence with tags>`
Blast Radius: `<what is reachable if exploited>`
Detection Gap: `<what monitoring is absent or insufficient>`
Validation:
1. `<operator validation step>`
2. `<operator validation step>`
3. `<operator validation step>`
Remediation: `<action> — <Microsoft framework name, section, URL>`

## Attack Path Scenarios

Only include the top scenarios that materially improve understanding of attacker options. Do not create a scenario where a direct standing privilege finding already communicates the risk clearly.

### PATH-1

ATTACK PATH `PATH-1`: `<title — attacker objective in one clause>`

Scenario Summary: `[CONFIRMED/DOCUMENTED/INFERRED/UNKNOWN]` `<2-line plain-language summary>`
Breach Premise: `[CONFIRMED/DOCUMENTED/INFERRED/UNKNOWN]` `<assumed starting compromise>`
Attacker Objective: `[CONFIRMED/DOCUMENTED/INFERRED/UNKNOWN]` `<specific end state>`
Why This Works: `[CONFIRMED/DOCUMENTED/INFERRED/UNKNOWN]` `<structural reason>`
Findings Enabling Path: `[CONFIRMED]` `<F-NNN, F-NNN, ...>`
Estimated Time: `[INFERRED]` `<rough time from Step 1 to objective>`

Step 1 — `<action label>`
`<descriptive narrative. name the mechanism. do not provide commands or payloads.>`
`[Evidence: CONFIRMED/DOCUMENTED/INFERRED — cite specific record or source]`

Step 2 — `<action label>`
`<descriptive narrative. name the mechanism. do not provide commands or payloads.>`
`[Evidence: CONFIRMED/DOCUMENTED/INFERRED — cite specific record or source]`

Detection Opportunities:
Step 1: `[CONFIRMED/DOCUMENTED/INFERRED/UNKNOWN]` `<what a defender would observe and in which log source>`. Detectability: `HIGH | MEDIUM | LOW | NONE`.
Step 2: `[CONFIRMED/DOCUMENTED/INFERRED/UNKNOWN]` `<what a defender would observe and in which log source>`. Detectability: `HIGH | MEDIUM | LOW | NONE`.

Analyst Notes:
`[CONFIRMED/DOCUMENTED/INFERRED/UNKNOWN]` Persistence achieved: `<yes/no — how access is maintained>`
`[CONFIRMED/DOCUMENTED/INFERRED/UNKNOWN]` Cross-tenant risk: `<yes/no>`
`[CONFIRMED/DOCUMENTED/INFERRED/UNKNOWN]` Data gaps: `<what is UNKNOWN that could change severity or feasibility>`

## Immediate Remediations

1. `<highest-priority action>`
2. `<second-priority action>`
3. `<third-priority action>`

## Investigative Commands

### Investigative Commands — PATH-1 / F-001

Run as: `<auditor identity / role required, e.g. Global Reader, Security Reader, Reader on subscription X>`

Confirm: `<claim being verified>`
```bash
<read-only command>
```
Expected: `<what a true positive looks like in the output>`
`[CONFIRMED/DOCUMENTED]` `<citation>`

Confirm: `<next claim>`
```bash
<read-only command>
```
Expected: `<what a true positive looks like in the output>`
`[CONFIRMED/DOCUMENTED]` `<citation>`

## Residual Risks And Data Gaps

- `<material residual risk>` `[CONFIRMED/INFERRED/UNKNOWN]`
- `<collection or visibility gap>` `[UNKNOWN]`
- `<operator follow-up item>` `[INFERRED]`
