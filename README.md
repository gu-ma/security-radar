# Security Radar

**Open-source vulnerability monitoring, without the noise.** Security Radar collects public vulnerability advisories, deduplicates overlapping records, tags technologies of interest, and publishes a searchable static dashboard. Microsoft Teams notifications are optional and independent of the monitoring engine.

> **Security boundary:** Watchlist matches indicate *possible relevance*, never confirmed exposure. This is not an asset scanner, institutional vulnerability assessment, or incident-response system.

## Status

**v0.2 / early pilot.** Implemented collectors: CISA Known Exploited Vulnerabilities, selected high/critical GitHub Global Security Advisories (including critical unreviewed advisories), critical NVD CVEs, and Red Hat Quay CVEs. The first live runs and GitHub Pages deployment must be confirmed in the [Actions tab](https://github.com/gu-ma/security-radar/actions). Source failures are displayed rather than silently treated as “no vulnerabilities.”

Other sources discussed (OSV, broader Red Hat products, Microsoft MSRC, Python, conda-forge, Docker) are documented in [sources and coverage](docs/SOURCES.md) as planned or supplementary: **they are not monitored by this version**. Never interpret a missing alert as proof that a vendor has no active vulnerabilities.

## Get started

1. Review [config/monitor.json](config/monitor.json) and edit the technology watchlist.
2. Visit [Actions → Monitor advisories and publish dashboard](https://github.com/gu-ma/security-radar/actions/workflows/monitor.yml) and choose **Run workflow**. It also runs automatically every six hours.
3. In repository **Settings → Pages → Build and deployment**, choose **GitHub Actions** as the source.
4. Set repository Actions variable `ENABLE_PAGES` to `true` under **Settings → Secrets and variables → Actions → Variables**. Run the monitor workflow again.
5. When deployment succeeds, open **https://apps.massol.me/security-radar/**.

The workflow writes public advisory JSON into `docs/data/` on the default branch. That is intentional; these files contain only public upstream advisory content, never a private institutional inventory. Repository settings may require allowing GitHub Actions to create commits (**Settings → Actions → General → Workflow permissions → Read and write permissions**). If the workflow cannot push, it reports an error; do not claim the published data is current.

### Run locally

Requires Python 3.11+ and standard library only:

```bash
python -m unittest discover -s tests -v
python -m security_radar
python -m http.server 8000 --directory docs
```

Visit http://localhost:8000. `python -m security_radar` accesses public endpoints. Set `GH_TOKEN` and/or `NVD_API_KEY` in the environment if rate limits necessitate them; they are not mandatory in principle. Never commit tokens. Initial collection creates a baseline and does **not** send a historical alert storm.

## How it works

```text
CISA KEV ──────┐
GitHub Advisories ─┼─> collectors ─> normalize + merge ─> keyword-watchlist triage
NIST NVD ──────┘                                      │
                                                      ├─> docs/data/*.json ─> GitHub Pages
                                                      └─> optional Teams Workflow webhook
```

- **Investigation:** CISA-listed exploitation + watchlist match. This *does not* mean local exposure.
- **Review:** High/critical severity + watchlist match, without confirmed exploitation in our environment.
- **Information:** Other advisories.
- **Unassessed:** The application does not know installed product versions, reachable assets, business impact, or whether a CVE applies to the university.

To add a source, place a module in `security_radar/adapters/` exposing `SOURCE_ID` and `collect(now, *, days)`. The registry discovers it automatically. Keep its public-only data mapping and tests alongside the adapter. See [source registry](docs/SOURCES.md).

The app merges records using shared identifiers (CVE/GHSA aliases), and preserves upstream source links. Advisory histories are retained for 180 days (configurable); NVD requests are limited to 110-day chunks and GitHub advisories to bounded pages, and may report errors when collection is incomplete. This is a pilot, not a completeness guarantee.

## Documentation

- [Project scope, implementation phases and acceptance criteria](docs/PROJECT.md)
- [Security sources, exact capabilities, and remaining adapters](docs/SOURCES.md)
- [Deployment, operation and troubleshooting](docs/OPERATIONS.md)
- [Teams integration and university-owner handoff](docs/TEAMS.md)
- [Security considerations and vulnerability reporting](SECURITY.md)

## Interface and design

The dashboard uses a restrained terminal-inspired theme: Inconsolata for headlines and UI labels, a readable system sans-serif for advisory text, dark graphite surfaces, high-contrast severity colors, and a subtle CSS-only radar motif. Copy is deliberately concise. No browser-side analytics, JavaScript animations, or image assets are needed for the decorative header. The externally hosted Google Fonts stylesheet is optional; a local monospace fallback remains available.

## Decision-first dashboard

The homepage highlights up to six watchlist-matched high/critical or KEV-listed advisories, with a prominent CVSS score, six technology categories and separate security-topic tags. Archive and homepage filters are deterministic, and search/category deep links can be shared. The full archive is collapsed by default. This **focus ranking is not proof of institutional exposure**. A critical vulnerability without an explicit technology match may stay in the full archive. Incomplete sources are shown in the dashboard status.

## Next on the roadmap

The following are recorded for a future iteration and **are not implemented yet**:

- **Archive sorting:** user-selectable order by newest/oldest publication, highest/lowest CVSS, severity, and attention priority. Preserve sorting when sharing a filtered deep link; handle unscored advisories explicitly.
- **RSS / Atom feed:** publish a standards-compliant public feed of selected advisories or updates (with stable IDs, links to the original advisory and Security Radar, category tags, and source timestamps). This should be generated from the same normalized data as the site and Teams adapter so downstream systems can subscribe without Microsoft 365 access. Ensure a bounded feed, clear selection criteria, and no leaked institutional details.

See [project roadmap](docs/PROJECT.md) for acceptance criteria.

## Teams: integration after university approval

Teams notifications are **off by default**. Use `python -m security_radar.notify --dry-run --alerts-file examples/sample_alerts.json` to preview the stable JSON contract without touching Microsoft 365. The payload is derived entirely from source data and fixed templates, not generated with AI. See [Teams handoff](docs/TEAMS.md) for the university owner's one-time test and explicit flow mapping.

An authorized Microsoft 365 user creates a **standard** channel named `Security Radar` and configures a Teams Workflows webhook flow. The Python notifier sends a short JSON payload `{"text": "..."}` to that flow; depending on the flow template, the receiver must map `triggerBody()?['text']` to a Teams **Post message in a chat or channel** action.

**Important:** The webhook is a credential: store it in the repository secret `TEAMS_WEBHOOK_URL`, then enable variable `ENABLE_TEAMS=true` only after completing the authorized test in [docs/TEAMS.md](docs/TEAMS.md). University policies may restrict HTTP triggers, workflow owners or inbound webhooks. Integration is designed, **not yet validated in the university tenant**.

## Project principles

Public data only • Source attribution • Explicit uncertainty • No arbitrary execution • Minimal dependencies • Reproducible offline unit tests • Optional notification destinations.

MIT licensed. Contributions and issue reports are welcome.
