# Source registry and coverage

**Four source adapters are implemented: CISA KEV, GitHub Advisories (restricted to high/critical), NIST NVD (critical CVSS v3), and the Red Hat Quay-specific CVE feed.** Listed vendors and databases are targets for future adapters or supplementary links, not proof of coverage.

| Source | Endpoint or authoritative reference | State | Purpose / caveat |
| --- | --- | --- | --- |
| CISA Known Exploited Vulnerabilities (KEV) | [JSON catalog](https://github.com/cisagov/kev-data) | **Implemented** | Positive evidence that a CVE is on KEV, not proof of exploitation of any particular machine |
| GitHub Advisory Database | [Global security advisories REST API](https://docs.github.com/en/rest/security-advisories/global-advisories) | **Implemented** | Reviewed high/critical and unreviewed critical advisories; includes vendor CVEs not yet package-reviewed |
| NIST National Vulnerability Database (NVD) | [CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | **Implemented** | Only recently modified CVSS v3 CRITICAL records (volume-limited); not complete NVD coverage |
| Open Source Vulnerabilities (OSV) | [OSV API](https://google.github.io/osv.dev/api/) | **Planned** | Query selected packages and versions; not a blanket RSS feed |
| Red Hat Quay | [Red Hat Security Data API](https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0/html-single/red_hat_security_data_api/index) | **Implemented — Quay only** | Queries the official product-filtered CVE listing, not all Red Hat products; reports API errors |
| Microsoft Security Response Center (MSRC) | [Security Update Guide](https://msrc.microsoft.com/update-guide) | **Planned** | Microsoft technologies; documented export/API options must be verified before implementing |
| Python Software Foundation | [Python security](https://www.python.org/dev/security/) | **Planned** | Interpreter/core ecosystem security; select appropriate official structured feed |
| conda-forge | [Security process](https://github.com/conda-forge/security) | **Planned** | Infrastructure disclosures and project security; not a universal feed of package CVEs |
| Docker | [Security announcements](https://docs.docker.com/security/security-announcements/) | **Planned** | Engine/Desktop advisories and container ecosystem |
| Additional Linux and cloud vendors | Their official PSIRTs/advisory endpoints | **Optional** | Added only with explicit adapter and verified coverage |

## Notes about the built-in adapters

**CISA KEV:** reads the public JSON dataset and selects CVEs added within the lookback. If a CVE is already in the retained list, it gains KEV status. There is no institutional asset mapping.

**GitHub advisories:** queries reviewed high/critical and unreviewed critical global advisories with a bounded page count, respecting API rate limits. Advisories without CVEs use a GHSA ID as their primary ID. Package ecosystems are extracted when supplied.

**NVD:** queries recently modified CVSS v3 CRITICAL CVEs only, paginates up to a bounded limit, extracts CVSS information and product tokens from CPEs. The parser intentionally does not pretend to determine exact vulnerable version ranges or local exploitability.

**Red Hat Quay:** the official CVE listing is queried using a product filter. Red Hat products outside Quay remain out of scope until dedicated adapters are added. An upstream API error is visible as source failure, not an empty successful source.

**OSV:** a future adapter should use monitored package inventory and batch version queries. Inventory must stay private if it contains institutional information; a public dashboard should use general-interest lists only.

**Other vendors:** require separate, tested machine-readable adapters. Some references above point to official advisory pages, not direct JSON/RSS endpoints. Do not scrape and silently label them “monitored.”

## Operational caveats

- API downtime, throttling, schema changes or partial results can create monitoring gaps.
- Scheduled workflows are not guarantees of exact delivery time.
- Watchlists are keyword matching rather than product and version resolution.
- Cross-source data quality and CVE propagation delays vary.
- For authoritative remediation instructions, always follow original vendor advisories.

**Focused watchlist ranking:** `config/monitor.json` has a `focus_topics` list used solely to rank the homepage shortlist. It does not affect CVE severity or assert local exposure. The GitHub unreviewed-critical query is restricted to a one-day lookback to control extreme feed volume; this is not complete historical coverage.

## Adding a new source adapter

Source adapters are discovered automatically in `security_radar/adapters/`. A new module needs a unique `SOURCE_ID` string and a callable `collect(now, *, days)` returning dictionaries created by `security_radar.model.make_advisory`. Define an explicit `DESCRIPTION` and add source-specific parser tests. Add the matching `collectors` entry to `config/monitor.json`, and update this file to reflect the actual coverage.

No changes to the dashboard, taxonomy, ranking or Teams notifier are necessary. Source text is untrusted data and must never execute as code. Do not mark a planned source as implemented before a successful live check.

### Deterministic tagging

Six broad categories are assigned by rules in `security_radar/taxonomy.py`: Applications, Libraries & dependencies, Containers & registries, Servers & infrastructure, Cloud & identity, and AI & ML tooling. Multiple categories may apply. Security topics are separate: Supply chain, Remote code execution, Privilege escalation, Authentication & authorization, Data exposure and Denial of service.

Unknown categories are marked `unclassified`. Keyword rules can produce false positives. None of these tags establishes affected software versions or university exposure.

Where provided, CVSS score and source/version are displayed. A missing version is marked as not provided rather than guessed. Explanation uses the original public summary, and the recommended next step is chosen from fixed, deterministic templates.
