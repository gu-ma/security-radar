# Security Radar : project specification

## Objective

Provide an independent, low-maintenance security intelligence tool collecting public advisories, detecting noteworthy vulnerability disclosures, and publishing a searchable dashboard. The public service works without access to a university Microsoft 365 tenant. Later, authorized university staff may connect selected alerts to a Microsoft Teams channel.

**Not in scope:** scanning university endpoints, verifying exploitation on assets, distributing confidential asset lists, making incident-response decisions, or guaranteeing a complete vulnerability inventory.

## Technical architecture

| Component | Implementation |
| --- | --- |
| Collection | Python 3, standard-library HTTP clients |
| Scheduling | GitHub Actions (twice daily at 00:17 and 12:17 UTC; not a real-time SLA) |
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

## Archive sorting and public feeds (implemented)

### Archive sorting

The archive has a separate sort control with attention priority, CVSS descending/ascending, severity descending, publication date ascending/descending, and update date ascending/descending. Missing scores and dates sort last in either direction. Sorting works with active filters, "show more" pagination and shared `?sort=...` deep links; Focus now retains its own fixed ranking. Node offline tests cover the comparator and missing values.

### Public RSS / Atom feed

The monitor generates `docs/rss.xml` (RSS 2.0) and `docs/atom.xml` (Atom 1.0) using the standard-library XML serializer. Both carry stable advisory IDs/deep links, original source links, publication/update timestamps, severity, and categorization. Eligibility: watchlist match and high/critical severity or CISA KEV listing. The 50 most recently updated eligible records are published; not all stored records. The output is deterministic for identical source data, with XML 1.0 control characters removed. CI validates the XML schemas at a structural level and exercises filtering, time formatting, and stable IDs. Feed files are generated on monitor runs without Microsoft credentials or a language model.

## Future: bounded repository growth

The active dataset already has a rolling 180-day modified-time window and a maximum of 2,500 records. RSS/Atom feeds contain only the 50 most recently modified qualifying advisories. These caps protect browser and feed consumers, but every scheduled write currently creates a new Git commit containing public JSON/XML snapshots, so **Git history accumulates**. Before substantially increasing polling frequency or coverage, redesign data publication as a workflow-built GitHub Pages artifact (or a separate bounded data branch/storage service) so generated snapshots are not repeatedly committed to `main`. Preserve cross-run state and deduplication in a reliable nonpublic execution store before removing the current persisted JSON. That change should be separately validated to avoid repeated notifications or loss of historical comparison state.

## Reliability and operations roadmap (November 2026)

The next steps are intentionally ordered, with one verifiable problem solved before adding new feeds. No recurring failure emails or Teams pings are enabled.

### Phase 1: collector reliability and source filtering (this iteration)

- [x] Replace unsupported numbered GitHub Global Advisory pages with GitHub Link-header cursors; reject repeated cursors, repeated records, malformed payloads, or an excessive page count.
- [x] Validate source-specific outer and important nested JSON fields before normalizing. Treat changed schemas as failures rather than an empty successful source.
- [x] Record a classified failure reason (schema, pagination, request/source, or unexpected), consecutive failures, first failure time, and last successful collection.
- [x] Add a multi-source origin filter to the archive and share the source choice in the URL. Source is distinct from affected vendor/product.
- [x] Test normal, missing-field, changed-schema, cursor-loop, and merged-source behavior offline.
- [ ] Verify a full live collection after deployment, particularly GitHub Advisories, and address any remaining provider-specific response changes before calling source health resolved.

### Phase 2: status and run history

- [ ] Build a low-noise, read-only `status.html` page linked from the dashboard header/status row. Keep the main focus view uncluttered.
- [ ] Publish a bounded run-history file (for example, last 30 to 60 monitoring runs) containing per-source status, elapsed time, counts, first/last error, last success, freshness and diagnostic category. Show timestamps in UTC and link to GitHub Actions run logs.
- [ ] Clearly distinguish healthy, degraded, stale, and failed; identify whether a zero-result batch was expected or an anomaly. Count anomalies across runs, not just a single result.
- [ ] Include a last-checked timestamp and show when GitHub Actions itself has not run on schedule. A workflow cannot directly detect its own absence: use an independent watchdog or external check.
- [ ] Never publish credentials, full untrusted response bodies, internal asset details or request authorization headers.

### Phase 3: deduplicated operational notifications

- [ ] Notify only when source status changes to failed/degraded, becomes stale for a configured threshold, or recovers. Avoid one notice per scheduled failure.
- [ ] Aggregate multiple failures into one incident, apply cooldowns and maintain a durable deduplication ledger. Make notification opt-in and test with fake transports.
- [ ] Use GitHub Issues or an approved email/health-monitoring workflow independent of university Teams. Confirm ownership and permissions before activation.
- [ ] Document the runbook for schema, pagination, quotas, authentication, and unexpected empty-result incidents.

### Phase 4: additional sources and relevance

- [ ] Add OSV package advisories (focus on affected ecosystems and watchlist matches).
- [ ] Evaluate Microsoft MSRC and broader Red Hat coverage before enabling them.
- [ ] Explore Python, conda-forge and Docker upstream sources where there is reliable vendor-provided data.
- [ ] Require source-specific schema fixtures, pagination tests, completeness checks, metadata links, rate-limit handling, and a demonstrated live sample for each new adapter.
- [x] Add distinct original-publication and recently-updated archive views, show both dates, and preserve source observation timestamps separately.
- [ ] Track significant upstream changes (affected ranges, fixed versions, severity changes, KEV transitions) with an evidence-based change ledger. Do not equate metadata revisions with new security patches.
- [ ] Consider EPSS and affected-product signals to improve prioritization without turning a generic CVSS score into a false institutional incident.
- [ ] Revisit `max_entries`, source quotas and archive retention as coverage increases; prioritize relevant records rather than keeping only a broad, severity-driven firehose.

### Phase 5: long-term state and delivery

- [ ] Remove generated snapshots from the normal Git history once equivalent persistent deduplication state exists.
- [ ] Add the notification change ledger (including meaningful updates to existing advisories).
- [ ] Complete a one-time Microsoft Teams acceptance test only with an authorized institutional owner.

## Operational status and collection history (implemented)

The dashboard has a separate `status.html` page using published, public-only monitoring metadata. Per-source cards display current result, last attempt, last success, last complete count, diagnostic category, failure streak, and error summary. A bounded `docs/data/history.json` holds the last 40 actual collection runs, including per-source snapshots, elapsed collection duration, affected source names and a direct GitHub Actions run link.

Code-only pushes do not add history. Health history starts on the first collection after this change. The page marks a status stale when the last recorded collection is older than 36 hours. This is a browser display heuristic, not an independent alert or availability guarantee.

On all-source failure, the collector saves failed status and history while retaining existing advisory and alert snapshots. The workflow persists and deploys that health result, then marks the monitor job failed. Do not infer clean source health from a green Actions deployment.

**Still planned:** independent missing-run watchdog, data-quality anomaly monitoring, GitHub Issue incident deduplication, recovery events, source-specific dashboards, and a robust notification ledger. Neither email nor Teams health notifications are enabled.

## Advisory lifecycle distinction (implemented November 2026)

GitHub's `modified` API query is retained for complete incremental synchronization, while each advisory stores its **original publication** separately from the **last source update** and Security Radar's **first observation**. The archive has 7/30-day new-publication and updated-existing filters with date-appropriate sorting, shareable URLs, and visible dates. New alert selection excludes previously unknown but years-old advisories merely reindexed or amended by an upstream feed. RSS/Atom intentionally remain high-signal **activity** feeds, because important metadata and KEV developments may apply to older disclosures. The project continues to merge GHSA IDs with CVE aliases across all sources.

**Future work:** Collect and compare per-source fixed versions and vulnerable ranges before claiming a genuinely new patch, distinguish a new KEV listing from a metadata-only update, and provide change-aware notifications without duplicating advisories.
