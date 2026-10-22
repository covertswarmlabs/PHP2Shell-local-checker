# php2shell_local_checker.py

Host-local vulnerability checker for **CVE-2026-109618** and **CVE-2026-109619** (PHP2Shell).

Run this script **on the server you want to assess**. It inspects PHP binaries, configuration, and package metadata to determine whether the host is affected.

## Why a local checker?

Remote scanning for PHP2Shell is fundamentally unreliable. External scanners can only work with what the server chooses to disclose, and in practice that is often nothing useful:

- **Version headers are frequently hidden.** `expose_php = Off` suppresses `X-Powered-By`, and reverse proxies, CDNs, and load balancers routinely strip or rewrite backend headers. Without a version string, an external scanner cannot determine patch status.
- **Vendor backports are invisible from outside.** Distributions like Debian, Ubuntu, and RHEL backport security fixes without changing the PHP version number. An external scanner sees `PHP/8.2.25` and flags it as vulnerable — but the binary may already contain the fix. There is no way to distinguish a backported build from an unpatched one based on the version string alone.
- **WAFs block the behavioural probes.** Cloudflare, Akamai, and ModSecurity already filter requests containing `PHP_SESSION_UPLOAD_PROGRESS` — the field name central to one of the attack paths. Any active probe that tries to test the vulnerable code path is stopped at the edge before it reaches PHP.
- **No safe behavioural difference exists on normal requests.** Lab testing confirms that vulnerable and patched PHP builds produce byte-identical responses to benign GET requests. The only observable differences require sending attack-shaped requests (multipart uploads, OOM triggers), which is destructive and inappropriate for production systems.

This script sidesteps all of those problems by running on the host itself, where it can read the actual PHP binary version, check for a definitive patch marker (`memory_hard_limit_percent` — an INI directive introduced by the fix commit), inspect configuration files directly, detect distro backports via package changelogs, and enumerate Docker containers. The result is a high-confidence verdict that no external scanner can match.

## Requirements

- Python 3.6+
- Read access to PHP binaries and config files
- Root recommended for full coverage (not required)

No external dependencies. Single file, stdlib only.

## Usage

```bash
# Human-readable output
python3 php2shell_local_checker.py

# JSON output
python3 php2shell_local_checker.py --json

# Save JSON report to file
python3 php2shell_local_checker.py --json --output /tmp/php2shell-report.json
```

Running as root (`sudo`) gives more complete coverage — it can discover PHP binaries in restricted directories, query FPM pool configs, and enumerate Docker containers. Without root, the script still works but may miss some installations. The report notes when coverage is incomplete.

## What it checks

For every PHP binary discovered on the system:

| Check | Why |
|-------|-----|
| **PHP version** | Compared against patched thresholds (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) |
| **Patch marker** (`memory_hard_limit_percent`) | INI directive introduced by the fix commit — definitively proves whether the fix is compiled in, catches vendor backports |
| **`session.upload_progress.enabled`** | Whether the primary attack path for CVE-2026-109619 is active |
| **SAPI** | cli, fpm, apache2handler, etc. — affects exploitability |
| **Distro backport detection** | Greps package changelogs for the CVE IDs |
| **Docker containers** | Queries running containers for PHP version and patch status |
| **Held/pinned packages** | Flags packages that won't auto-update |

## Verdicts

| Verdict | Meaning | Exit code |
|---------|---------|-----------|
| `PATCHED` | Fix is present (version ≥ fixed release, or patch marker found) | 0 |
| `NOT_AFFECTED` | PHP predates the vulnerable feature | 0 |
| `VULNERABLE` | Unpatched, on a supported branch | 1 |
| `EOL_VULNERABLE` | Unpatched, on an end-of-life branch — no upstream fix will ever exist | 1 |
| `MITIGATED` | Unpatched, but `upload_progress` is disabled (partial — CVE-2026-109618 is NOT mitigated) | 1 |
| `EOL_MITIGATED` | EOL + `upload_progress` disabled | 1 |
| `UNKNOWN` | Could not determine patch status | 1 |

Exit code 0 means every assessed runtime is confirmed safe. Exit code 1 means at least one finding requires attention — including MITIGATED and UNKNOWN, which do not confirm safety.

## Safety

- **No network traffic** — runs entirely locally
- **No files modified** (unless `--output` is used to write a report)
- **No exploit payloads** — all checks are read-only queries against PHP binaries and package managers

## Coverage limitations

- Checks installed binaries on disk, not necessarily what a running Apache/FPM worker has loaded in memory
- Does not verify that workers were restarted after a package update
- Docker containers without an accessible `php` CLI binary are skipped
- PHP installations in non-standard locations not covered by the search list may be missed
- Running as non-root may miss binaries in restricted directories

## References

- [CVE-2026-109618 — GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 — GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- Fixed in PHP **8.2.35, 8.3.36, 8.4.27, 8.5.12** (released 2026-10-21)
