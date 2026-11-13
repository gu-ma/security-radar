# Source registry and coverage

**Only the first three sources below have working collectors in v0.1.** Listed vendors and databases are targets for future adapters or supplementary links, not proof of coverage.

| Source | Endpoint or authoritative reference | State | Purpose / caveat |
| --- | --- | --- | --- |
| CISA Known Exploited Vulnerabilities (KEV) | [JSON catalog](https://github.com/cisagov/kev-data) | **Implemented** | Positive evidence that a CVE is on KEV, not proof of exploitation of any particular machine |
| GitHub Advisory Database | [Global security advisories REST API](https://docs.github.com/en/rest/security-advisories/global-advisories) | **Implemented** | Reviewed GHSA advisories; package-level data when supplied |
| NIST National Vulnerability Database (NVD) | [CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | **Implemented** | CVSS and CPE descriptions; processing and analysis can lag upstream disclosures |
| Open Source Vulnerabilities (OSV) | [OSV API](https://google.github.io/osv.dev/api/) | **Planned** | Query selected packages and versions; not a blanket RSS feed |
| Red Hat | [Security data](https://access.redhat.com/security/data) | **Planned** | RHSA notices, Red Hat products, Quay-related advisories |
| Microsoft Security Response Center (MSRC) | [Security Update Guide](https://msrc.microsoft.com/update-guide) | **Planned** | Microsoft technologies; documented export/API options must be verified before implementing |
| Python Software Foundation | [Python security](https://www.python.org/dev/security/) | **Planned** | Interpreter/core ecosystem security; select appropriate official structured feed |
| conda-forge | [Security process](https://github.com/conda-forge/security) | **Planned** | Infrastructure disclosures and project security; not a universal feed of package CVEs |
| Docker | [Security announcements](https://docs.docker.com/security/security-announcements/) | **Planned** | Engine/Desktop advisories and container ecosystem |
| Additional Linux and cloud vendors | Their official PSIRTs/advisory endpoints | **Optional** | Added only with explicit adapter and verified coverage |

## Notes about the built-in adapters

**CISA KEV:** reads the public JSON dataset and selects CVEs added within the lookback. If a CVE is already in the retained list, it gains KEV status. There is no institutional asset mapping.

**GitHub advisories:** queries reviewed global advisories with a bounded page count, respecting API rate limits. Advisories without CVEs use a GHSA ID as their primary ID. Package ecosystems are extracted when supplied.

**NVD:** queries recently modified CVEs, paginates up to a bounded limit, extracts CVSS information and product tokens from CPEs. The parser intentionally does not pretend to determine exact vulnerable version ranges or local exploitability.

**OSV:** a future adapter should use monitored package inventory and batch version queries. Inventory must stay private if it contains institutional information; a public dashboard should use general-interest lists only.

**Other vendors:** require separate, tested machine-readable adapters. Some references above point to official advisory pages, not direct JSON/RSS endpoints. Do not scrape and silently label them “monitored.”

## Operational caveats

- API downtime, throttling, schema changes or partial results can create monitoring gaps.
- Scheduled workflows are not guarantees of exact delivery time.
- Watchlists are keyword matching rather than product and version resolution.
- Cross-source data quality and CVE propagation delays vary.
- For authoritative remediation instructions, always follow original vendor advisories.
