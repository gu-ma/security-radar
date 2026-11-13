# Operations

## Initial bootstrap

1. Review the source registry, public/private information boundaries and watchlist.
2. Open **GitHub Actions → Monitor advisories and publish dashboard → Run workflow**.
3. Review the latest job logs, particularly per-source success and warnings.
4. Open `docs/data/status.json` for `sources`, `partial`, `last_successful_run` and `source_errors`.
5. Enable GitHub Pages source **GitHub Actions** under repository settings; add variable `ENABLE_PAGES=true`. Run workflow again.
6. Visit `https://gu-ma.github.io/security-radar/` after a successful deploy.

If repository protection or Actions token restrictions block pushes, a repository administrator must approve a persistence strategy. Do not weaken protections without approval.

## Configuration

Edit `config/monitor.json`: `watchlist` contains case-insensitive search phrases, `collectors` enables/disables implemented adapters, `retention_days` controls retained recent advisories and `max_entries` caps static JSON size.

This watchlist is broad and may generate false positives. It does not contain internal assets, and must not be described as an institutional software inventory.

## Run locally

```bash
python -m unittest discover -s tests -v
python -m security_radar
python -m http.server 8000 --directory docs
```

No pip install is necessary; Python 3.11+ is recommended. Internet access is required to collect advisories.

## Source health

NVD, GitHub, CISA and Red Hat Quay each report a last success timestamp and current state. If one fails, old data is retained and the dashboard notes partial success; investigate authentication and rate limits. If **all** fail, the monitor exits nonzero and does not overwrite previously successful data.

Potential limits: NVD no-key rate limiting, NVD record volume, GitHub API quotas, CISA JSON availability and scheduled workflow delays. The first run is a baseline, not an incident event.

## Deployment and schedules

- Workflow scheduled every six hours at minute 17 UTC, plus manual dispatch.
- Generated public JSON files are committed back to `main`.
- For a new repository, GitHub Pages settings and variable `ENABLE_PAGES` are **manual administrator steps**.
- Pushes performed by GitHub Actions' built-in token may not trigger other push-based workflows; this workflow deploys in the same run.
- GitHub scheduled workflows may be delayed or disabled after inactivity.

## Security checklist

- Minimal token permissions, external data never executed, HTML inserted using `textContent`.
- No private inventories in public JSON; never put `TEAMS_WEBHOOK_URL` into client JavaScript.
- Treat Teams webhook URLs as passwords and rotate if exposed.
- Keep Actions dependencies updated and pin to commit SHAs for hardened deployments.
- Periodically test a duplicate advisory, a missing upstream response and a stale source.

## Known MVP limitations

- Priority watchlist is keyword-only.
- A source already processed may later update: new KEV status is merged but **updated existing advisories do not yet generate another Teams alert**.
- Polling and advisory storage have bounded sizes; see code for limits.
- No operational on-call guarantee or complete source coverage.
- The optional Teams notifier has not been exercised against a real tenant.

## v0.2 validation

Run `python -m unittest discover -s tests -v` and `python -m security_radar.notify --dry-run --alerts-file examples/sample_alerts.json` to validate the full offline Teams payload contract. The latter makes no HTTP requests.

The monitor uses dynamic modules in `security_radar/adapters/`. After adding an adapter, check both offline tests and live `docs/data/status.json` source health before describing it as active.

Tagging, category-specific next steps, and official explanations are entirely deterministic. False-positive categorization is possible; update the explicit rules and tests when needed.

Teams notification is disabled unless the authorized university owner has confirmed a Workflow test and the repository owner enables `ENABLE_TEAMS`.

## Sorting and syndication

The archive supports client-side sorting by attention/relevance, CVSS ascending/descending, severity, publication date and last-updated date. Missing CVSS and timestamps are placed last. Sort choice is shareable through the `sort` URL parameter and composes with category/topic filters. Sorting is implemented in `docs/sorting.js` and tested with `node --test tests/test_sorting.cjs`.

The monitor generates **RSS 2.0** and **Atom 1.0** on every successful collection:

- `https://apps.massol.me/security-radar/rss.xml`
- `https://apps.massol.me/security-radar/atom.xml`

Run `python -m security_radar.feeds` locally to rebuild them from `docs/data/advisories.json`. Feed entries are recent, watchlist-relevant high/critical or KEV-listed records, limited to 50. Old records can remain in the dashboard but leave the feed as newer records displace them. GUIDs are stable canonical advisory deep links; consumers should use GUID/Atom ID to deduplicate. The feeds are public and make no claim about university exposure.

**Storage limits:** `retention_days=180` and `max_entries=2500` bound the current JSON in `config/monitor.json`; the feed caps output at 50. Git history still retains old committed snapshots. A future optimization is to publish GitHub Pages artifacts without rewriting tracked generated data at every scheduled run. This requires designing persistent deduplication state separately before switching, to avoid repeated Teams notifications.

## Observation timestamps

`first_seen` records when Security Radar first collected a specific advisory and is immutable across normal subsequent collection runs. `last_seen` records the last time any enabled source returned that advisory. Neither is the vendor's `published` or `modified` timestamp. A former bug caused `first_seen` to reset whenever the saved JSON was reloaded; regression tests now cover repeated runs, absent source observations, and cross-source alias merges. On 2026-11-13 the earliest observations were restored for the then-current 295 records from earlier Git-committed snapshots. No timestamps earlier than the first available repository snapshot can be inferred.
