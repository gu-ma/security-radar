# Teams integration: university owner handoff

Security Radar runs independently of Microsoft 365. It is ready to **produce and validate JSON notification payloads offline**; delivery to the university Teams channel is **not verified** and requires a one-time acceptance test by an authorized Microsoft 365 owner.

## 1. Exact responsibility split

| Security Radar maintainer | University Microsoft 365 / Teams owner |
| --- | --- |
| Maintains collectors, taxonomy, ranking and static dashboard | Creates a **standard** `Security Radar` channel in the existing Team |
| Builds notification payloads from public source data | Creates an approved cloud Workflow to receive requests and post messages |
| Runs payload-schema, escaping, size and simulated HTTP tests | Configures trigger authentication, posts to the correct Team/channel and tests |
| Stores the approved Workflow URL in GitHub Actions Secrets | Manages Workflow co-owners, tenant policy and revocation |
| Enables Teams only after owner signoff | Confirms that a sample alert visibly reaches the channel |

**Suggested channel description:** "Public cybersecurity advisories, software supply-chain vulnerabilities, and security updates relevant to development and research. Notifications are investigation leads, not verified local exposure or incident declarations."

## 2. Preferred architecture

```text
GitHub Actions / Python
  -> public advisory collection
  -> deterministic categories, priority, CVSS and fixed action template
  -> select NEW high-impact watchlist-relevant alerts
  -> POST {"text":"..."} to authorized Teams Workflows HTTP trigger
  -> Flow: Post a message in a chat or channel
  -> # Security Radar
```

Use **Teams Workflows**, rather than retired Office 365 Connectors. The receiver should be a *custom Workflow* with a webhook trigger explicitly configured for the envelope documented here. A canned "Post card on incoming webhook" template may require an Adaptive Card/MessageCard body instead and is **not guaranteed to accept `{"text": ...}` unchanged**. An authorized admin must select and configure a compatible flow.

## 3. HTTP and data contract

Content type: `application/json`. HTTP method: `POST`. UTF-8 encoded object with exactly one property:

```json
{
  "text": "Security Radar | New advisories\n\nPublic-source investigation leads. Local exposure has NOT been assessed.\n\n[CRITICAL | CVSS 9.8] CVE-2026-123710 | Containers & registries\nQuay signing-key security vulnerability\nWhy it matters: An attacker could modify affected container registry signing keys.\nNext step: Consult the vendor advisory and verify affected versions.\nSource: https://access.redhat.com/security/cve/CVE-2026-123710\nDetails: https://apps.massol.me/security-radar/?q=CVE-2026-123710#findings"
}
```

This is a **public synthetic sample**. No language model or generated text is involved. The main application builds the text using source titles/summaries, known metadata and deterministic next-step templates.

The Workflow trigger schema can be:

```json
{
  "type": "object",
  "properties": {
    "text": { "type": "string" }
  },
  "required": ["text"]
}
```

The Workflow's posting action must explicitly map **the trigger body property `text`** (for example, `triggerBody()?['text']`) to its message field. The action must select the actual Team and channel. Depending on the tenant, authentication, trigger settings and connector details may differ. If the selected template expects Adaptive Card objects, the owner must use a compatible custom flow or request a separately implemented card adapter.

The Python sender treats HTTP 200/201/202 as **trigger accepted**, not proof that the Teams message appeared. Other HTTP statuses cause a visible error. The university owner must inspect the actual channel and Workflow run history.

## 4. Verify without any Teams account

From the repository root, no tokens required:

```bash
python -m unittest discover -s tests -v
python -m security_radar.notify --dry-run --alerts-file examples/sample_alerts.json
python -m security_radar.notify --dry-run --alerts-file examples/sample_alerts.json --preview-file /tmp/security-radar-teams-preview.json
```

These commands make **no network calls**. Tests cover selection rules, category filtering, JSON encoding, CVSS display, original URL/deep link, payload validation, maximum size, mocked HTTP POST, invalid endpoint rejection, and missing data.

**No one should enable Teams notifications only on the strength of offline tests.** These prove the Python-side contract, not Microsoft 365 configuration.

## 5. Authorized one-time activation

1. Get agreement from university IT/security about the use of public advisories and external webhook triggers.
2. Create the standard `Security Radar` channel inside the existing Team.
3. Create a Teams Workflow with webhook HTTP trigger (from the supported Workflows interface). Choose trigger authentication permitted by tenant policy. If an unauthenticated webhook is approved, treat the URL like a password. An authenticated flow may require a different client adapter.
4. Define the JSON trigger schema above and map `text` into **Post a message in a chat or channel**. Disable automatic mentions.
5. Send a harmless controlled test: `{"text":"Security Radar test. No incident; please confirm this message arrived."}`.
6. Confirm exactly one visible post in the intended channel and inspect failed/succeeded workflow runs.
7. Have the GitHub maintainer store the private endpoint in Actions secret `TEAMS_WEBHOOK_URL`, and set repository variable `ENABLE_TEAMS=true`.
8. Check the GitHub Action next run and verify actual channel receipt. Keep at least two university Workflow co-owners.
9. If any step fails, set `ENABLE_TEAMS=false` and investigate. Keep all webhook URLs out of logs, Issues, README and the public Pages build.

## 6. What will be sent

- Only **new** advisories with a watchlist match and high/critical severity or CISA KEV listing.
- At most six advisories per message, using a shared format with CVSS score, technology categories, official source URL, deterministic explanation and suggested action, and dashboard deep link.
- One summary per monitoring execution if qualifying records were found.
- Default Teams integration state: **disabled**.

A scheduled GitHub workflow is not an immediate alert service: runs can be delayed, and results can lag upstream publication. Follow institutional incident response practices for active incidents.

**Known limitation:** The current engine treats an already-seen advisory as already notified, even if its severity or KEV status later changes. Robust change detection and a durable notification ledger are future hardening tasks. Do not rely on this as the sole source of urgent security notices.

## 7. If external webhooks are blocked

University IT can instead create an approved scheduled Workflows process that retrieves the public JSON at `https://apps.massol.me/security-radar/data/alerts.json`, selects permitted entries, and posts to Teams. Authentication, connector availability, and tenant licensing must still be checked by the institutional owner.

## 8. Official Microsoft references

- [Microsoft: send a message in Teams from Power Automate](https://learn.microsoft.com/en-us/power-automate/teams/send-a-message-in-teams)
- [Microsoft Teams Workflows overview](https://learn.microsoft.com/en-us/power-automate/teams/teams-overview)
- [Webhooks and connectors in Microsoft Teams](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)
