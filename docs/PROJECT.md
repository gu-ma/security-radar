# Security Radar — project specification

## Objective

Provide an independent, low-maintenance security intelligence tool collecting public advisories, detecting noteworthy vulnerability disclosures, and publishing a searchable dashboard. The public service works without access to a university Microsoft 365 tenant. Later, authorized university staff may connect selected alerts to a Microsoft Teams channel.

**Not in scope:** scanning university endpoints, verifying exploitation on assets, distributing confidential asset lists, making incident-response decisions, or guaranteeing a complete vulnerability inventory.

## Technical architecture

| Component | Implementation |
| --- | --- |
| Collection | Python 3, standard-library HTTP clients |
| Scheduling | GitHub Actions (every six hours; not a real-time SLA) |
| State | Versioned JSON in `docs/data`; first-run baseline |
| Normalization | CVE/GHSA alias merge, source links, CVSS/severity, KEV signal |
| Prioritization | Configurable watchlist keyword matches |
| Dashboard | Static HTML/CSS/JS through GitHub Pages |
| Notifications | Optional JSON HTTP POST to an approved Teams Workflow |
| Credentials | GitHub Actions secrets, never in static output |
| Testing | Offline `unittest` fixtures and CI |

## Data model

Each advisory contains: ID, title, summary, severity, optional CVSS score, `exploited` (true only when observed in CISA KEV), aliases, affected product strings, ecosystems, source name/URL pairs, publication/update timestamps, first/last seen, matched watchlist topics, priority and `exposure: not assessed`.

Data source coverage must be disclosed. `docs/data/status.json` includes source-specific last successes and failures.

## Prioritization rules

- **Investigate**: a CISA KEV-listed advisory matches the watchlist. Fast triage may be warranted, but affected institutional assets must still be established.
- **Review**: high/critical severity matches an interest topic.
- **Information**: all other retained advisories.

Never equate a CVSS score or a watchlist match with confirmed local exposure. “Immediate” delivery is only possible subject to polling interval, GitHub Actions schedule behavior and downstream authorization.

## User experience

Dashboard: a six-item focus view for high-impact watchlist matches, a collapsed full searchable archive, status/last synchronization, and official advisory links. The UI never claims institutional exposure. Data are deliberately rendered as text, not HTML, to avoid cross-site scripting through untrusted advisory content.

## Phased roadmap

1. **MVP:** CISA KEV, selected high/critical GitHub Advisories, critical NVD, Red Hat Quay CVEs, offline tests, generated JSON.
2. **Public website:** GitHub Pages deployment and source-health indicators.
3. **Expanded sources:** OSV package queries; Red Hat; Microsoft MSRC; Python; conda-forge; Docker. Each requires adapter tests, source/coverage checks and rate-limit review.
4. **Institutional integration:** Teams Workflow/webhook, university approval, operational ownership, monitored technologies.
5. **Hardening:** robust incremental cursors, recurring-alert updates, vendor metadata enrichment, dashboards for errors, stronger record entity resolution, notification delivery ledger.

## Acceptance criteria

- [ ] All three MVP collectors return valid records when live-tested.
- [ ] Offline tests pass.
- [ ] One upstream feed failing cannot destroy existing data.
- [ ] Partial success is visibly marked.
- [ ] Records have original source URLs and distinguish published vs. modified.
- [ ] GitHub Pages is enabled and visibly displays recent items.
- [ ] Sensitive data and private asset inventory are never written to Pages.
- [ ] New reports do not generate a storm of historical Teams notifications.
- [ ] Teams is not enabled before an authorized owner tests the Workflow endpoint.
- [ ] Source coverage and missing sources are clearly documented.
- [ ] Workflow runs are monitored and a backup maintainer is designated.

## Responsibilities

**Independent developer:** monitoring code, tests, data quality, public dashboard, documentation.  
**University Team owner / authorized IT:** channel creation, Teams Workflows endpoint, tenant policy, authentication and ongoing ownership.  
**Security stakeholders:** scope the relevant technologies and decide escalation based on actual asset information.

A public monitoring result is an investigation lead, not a university security incident declaration.

## v0.2 decision-first design

- CVSS score and version are prominent at top right; unknown scores/versions are marked as such.
- Technology category is a multi-label attribute with six known values, plus `unclassified` for insufficient evidence.
- Security topics describe vulnerability mechanism and are separate from technology category.
- "Why it matters" is derived from original advisory text, never from unverified AI-generated explanations.
- "Suggested next step" is a conservative rule-based template. It does not state that institutional infrastructure is affected.
- The focus view shows up to six significant watchlist leads. The full archive has distinct technology/topic/severity/priority/KEV filters, and supports shareable search/category links.
- Teams uses the same structured fields and deterministic filters, but does not replace the dashboard. Only selected new alerts are eligible for notification.
- Adapter discovery is modular: add a module plus tests and configuration, not UI or notification code.
- Teams acceptance has two independent gates: offline Python payload/HTTP tests and an actual approved university Workflow post. The second cannot be performed from an unconnected local development environment.

## Planned follow-ups (not in this style/content release)

### Archive sorting

Add a sort control separate from category, severity and priority filtering. Choices: attention priority, CVSS descending/ascending, severity descending, newest publication first, and oldest publication first. Unknown scores should sort consistently rather than being treated as 0. Sorting must work with active filters, pagination and shared deep links, with explicit labels for publication versus last-modified dates.

### Public RSS / Atom feed

Generate a standards-compliant RSS 2.0 or Atom feed at a stable URL beneath the GitHub Pages site using existing normalized public advisories. Include GUID/id, title, original source URL, Security Radar deep link, published/updated timestamps, severity, and technology categories, escaping XML safely. Choose a clear inclusion rule (for example, high-signal watchlist leads only) and keep a bounded history. Validate XML in CI and add a documented subscription URL for integration into other systems, including Microsoft Teams and RSS readers. Avoid duplicating old items or asserting institutional exposure. Feed generation must work without an LLM, a database server, or Microsoft credentials.
