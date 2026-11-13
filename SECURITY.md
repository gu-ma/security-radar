# Security policy

Security Radar collects public, potentially untrusted advisory text. Never run or copy code embedded in an advisory and never infer institutional exposure from a public watchlist match.

To report a vulnerability in Security Radar, use GitHub private vulnerability reporting if enabled on this repository, or contact its maintainers privately. Please avoid disclosing keys, webhook URLs, personal data, or university asset inventories in public issues.

## Trust boundaries

- External APIs: data-only, bounded JSON responses, network timeouts, limited retries.
- GitHub Actions: may access repository secrets, so workflow changes must be reviewed.
- GitHub Pages: contains public advisories only; no organizational assets.
- Teams: optional; endpoint address is a secret and is never published.
- Source failures and monitoring incompleteness are explicitly shown.

This tool is not a substitute for university security operations or vendor-led incident response.
