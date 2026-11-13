# Microsoft Teams integration — owner handoff

The **core monitoring tool runs without any Microsoft permissions**. This document is for an authorized university Microsoft 365 / Teams owner who will add a Teams destination later.

## What the university team should create

| Setting | Suggested value |
| --- | --- |
| Team | Existing university Microsoft Team |
| Channel | `Security Radar` |
| Visibility | Standard channel, visible to Team members |
| Channel description | Automated cybersecurity advisories and software supply-chain updates. Alerts are untriaged until their impact on our infrastructure has been verified. |
| Workflow owner | Institutionally authorized account |
| Backup owner | Second authorized maintainer |
| Escalation | Existing university IT/security processes |

## Recommended supported integration

Use **Microsoft Teams Workflows**, not retired Office 365 Connectors.

1. The authorized owner opens Teams → Workflows or Microsoft Power Automate (subject to tenant access).
2. Choose a template based on **When a Teams webhook request is received** / **Send webhook alerts to a channel**, or create an equivalent cloud flow.
3. Configure the trigger's access controls and authentication appropriately. Do not assume anonymous callers are permitted under university policy.
4. Add an action **Post a message in a chat or channel**, select the existing Team and `Security Radar` channel.
5. Map the incoming request's `text` field to the posted message (an expression in Power Automate may be `triggerBody()?['text']`). Test this mapping with a benign payload.
6. Restrict any anonymous webhook URL as a high-value secret; do not post it in Teams or public documentation.
7. Only after a successful local test, the GitHub repository owner sets Actions secret `TEAMS_WEBHOOK_URL` and variable `ENABLE_TEAMS=true`.
8. The monitor workflow posts **one summary message per run** if it finds new watchlist-relevant advisories (up to 20 alerts, summarized in one Teams message).

The Python notifier sends JSON like:

```json
{"text": "Security Radar: 1 new advisory for review\nWatchlist relevance is not verified exposure.\nhttps://example.org/advisory"}
```

**Important:** Teams workflows vary in required body shape, auth policy and flow actions. The receiver may need a JSON schema for `text`. A direct POST to a webhook *is not the same as* guaranteed delivery to a Teams channel; both the trigger and posting action must be enabled and correctly wired.

## Testing checklist

- [ ] Team/channel and workflow are approved by university IT.
- [ ] Only authorized workflow owners and co-owners can edit or view the webhook.
- [ ] A harmless test `{"text":"Security Radar test — no incident"}` reaches the correct channel exactly once.
- [ ] The flow prevents unintended everyone-mentions and avoids private environment details.
- [ ] Webhook URL stored only in GitHub Actions Secrets.
- [ ] Variable `ENABLE_TEAMS` set to `true` only after test succeeds.
- [ ] GitHub workflow publishes normal advisory data even if Teams posting fails.
- [ ] Maintainers know how to rotate/revoke the webhook and disable the notifier.

## If inbound webhooks are disallowed

Ask university IT to implement an institutionally owned scheduled Power Automate workflow that retrieves the **public** `docs/data/alerts.json` file via an approved connector and posts approved alerts into Teams. This may require additional licenses/permissions; it must be evaluated by tenant administrators.

## Safety and semantics

A high CVSS score does not justify an `@everyone` message by itself. The monitoring tool has no local inventory and cannot confirm institutional exposure. Urgent incident escalation remains the responsibility of authorized security staff.

## Microsoft references

- [Microsoft Power Automate — send a message in Teams](https://learn.microsoft.com/en-us/power-automate/teams/send-a-message-in-teams)
- [Microsoft Teams Workflows overview](https://learn.microsoft.com/en-us/power-automate/teams/teams-overview)
- [Microsoft Teams webhook workflow guidance](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)
