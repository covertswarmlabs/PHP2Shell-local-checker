#!/usr/bin/env python3
"""Host-local vulnerability checker for CVE-2026-109618 / CVE-2026-109619 (PHP2Shell).

Run this script ON the server you want to assess.  It reads PHP binaries,
configuration files, package manager metadata, and (optionally) queries running
PHP-FPM pools to determine whether the host is affected.

It does NOT:
  - send any network traffic to external hosts
  - execute any exploit payload or memory-corruption trigger
  - require network access of any kind

When --output is used, a single report file is written.  All other operation
is read-only.

Exit codes:
  0 — Every assessed PHP runtime is PATCHED or NOT_AFFECTED.
  1 — At least one finding is VULNERABLE, EOL_VULNERABLE, MITIGATED,
      EOL_MITIGATED, or UNKNOWN.  MITIGATED and UNKNOWN return 1 because
      they do not confirm the absence of exposure; automation should not
      treat them as a clean result.
  2 — The script itself encountered an error.

Coverage limitations:
  This tool inspects PHP binaries reachable on disk and Docker containers
  with a CLI binary.  It does NOT verify:
    - which PHP build is loaded by a running Apache/FPM worker (the on-disk
      binary may differ from what the worker has mmap'd);
    - that workers were restarted after a package update;
    - containers that lack a 'php' CLI binary or restrict exec;
    - PHP installed in locations not covered by the search list.
  Findings describe the installed state.  A separate restart/reload
  verification is needed to confirm the serving runtime matches.

Requires: Python 3.6+, read access to PHP binaries and config files.
          Root recommended for full coverage (FPM pool inspection, package
          manager queries, Docker container enumeration).

Usage:
  sudo python3 php2shell_local_checker.py
  sudo python3 php2shell_local_checker.py --json
  sudo python3 php2shell_local_checker.py --json --output /tmp/php2shell-report.json
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOOL_VERSION = "1.2.0"
TOOL_NAME = "php2shell-host-checker"

ADVISORIES = {
    "CVE-2026-109618": "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "CVE-2026-109619": "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
}

# Official patched versions per supported branch.
FIXED_BY_BRANCH: Dict[Tuple[int, int], Tuple[int, int, int]] = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

# Branches that are end-of-life and will never receive an official patch.
EOL_BRANCHES = {
    (5, 0), (5, 1), (5, 2), (5, 3), (5, 4), (5, 5), (5, 6),
    (6, 0),
    (7, 0), (7, 1), (7, 2), (7, 3), (7, 4),
    (8, 0), (8, 1),
}

# session.upload_progress was introduced in PHP 5.4.0.
UPLOAD_PROGRESS_SINCE = (5, 4, 0)

CVE_IDS = "CVE-2026-109618|CVE-2026-109619"
CVE_109618 = "CVE-2026-109618"
CVE_109619 = "CVE-2026-109619"

# INI directive registered in main/main.c by every fix commit.  Its presence
# means the build contains the fix — even if the version string hasn't changed
# (vendor backports).  Lab-validated by the php2shell-check research team (H4).
PATCH_MARKER_DIRECTIVE = "memory_hard_limit_percent"

# Binaries that are PHP build/dev tools, not runtimes.  Their UNKNOWN verdict
# should not override a definitive runtime verdict.
BUILD_TOOL_BASENAMES = frozenset({
    "php-config", "phpize", "phpdbg", "php-cgi-bin",
    "pear", "pecl", "phar", "phar.phar",
})

# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

VERDICT_PATCHED = "PATCHED"
VERDICT_VULNERABLE = "VULNERABLE"
VERDICT_MITIGATED = "MITIGATED"
VERDICT_EOL_VULNERABLE = "EOL_VULNERABLE"
VERDICT_EOL_MITIGATED = "EOL_MITIGATED"
VERDICT_NOT_AFFECTED = "NOT_AFFECTED"
VERDICT_UNKNOWN = "UNKNOWN"

# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def parse_version(version_str: str) -> Optional[Tuple[int, int, int]]:
    """Parse '8.4.4' into (8, 4, 4).  Returns None on failure."""
    m = VERSION_RE.match(version_str.strip())
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def is_prerelease(version_str: str) -> bool:
    """True if version string contains dev/alpha/beta/RC suffix."""
    remainder = VERSION_RE.sub("", version_str.strip())
    return bool(re.search(r"(?i)(dev|alpha|beta|rc)\d*", remainder))


def branch_of(version: Tuple[int, int, int]) -> Tuple[int, int]:
    return (version[0], version[1])


def version_str(version: Tuple[int, int, int]) -> str:
    return f"{version[0]}.{version[1]}.{version[2]}"


# ---------------------------------------------------------------------------
# Shell helpers (safe, read-only commands only)
# ---------------------------------------------------------------------------

def run_cmd(cmd: List[str], timeout: int = 15) -> Optional[str]:
    """Run a command, return stdout or None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError,
            OSError):
        pass
    return None


def which(name: str) -> Optional[str]:
    """Find an executable on PATH."""
    for d in os.environ.get("PATH", "/usr/bin:/usr/local/bin").split(":"):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return os.path.realpath(p)
    return None


def _is_build_tool(binary: str) -> bool:
    """True if the binary is a PHP build/dev utility, not a runtime."""
    return os.path.basename(binary) in BUILD_TOOL_BASENAMES


# ---------------------------------------------------------------------------
# PHP binary discovery
# ---------------------------------------------------------------------------

# Common PHP binary locations across distros and hosting panels.
PHP_SEARCH_GLOBS = [
    "/usr/bin/php*",
    "/usr/local/bin/php*",
    "/usr/sbin/php-fpm*",
    "/usr/local/sbin/php-fpm*",
    "/opt/cpanel/ea-php*/root/usr/bin/php",
    "/opt/cpanel/ea-php*/root/usr/sbin/php-fpm",
    "/opt/alt/php*/usr/bin/php",
    "/opt/alt/php*/usr/sbin/php-fpm",
    "/opt/plesk/php/*/bin/php",
    "/opt/plesk/php/*/sbin/php-fpm",
    "/opt/remi/php*/root/usr/bin/php",
    "/opt/remi/php*/root/usr/sbin/php-fpm",
    "/www/server/php/*/bin/php",
    "/www/server/php/*/sbin/php-fpm",
    "/usr/local/lsws/lsphp*/bin/php",
    "/usr/local/php*/bin/php",
    "/usr/local/php*/sbin/php-fpm",
]


def discover_php_binaries() -> List[str]:
    """Find all PHP CLI and FPM binaries on the system."""
    import glob as glob_mod

    seen: set = set()
    binaries: List[str] = []

    # Start with whatever is on PATH.
    for name in ("php", "php-fpm"):
        path = which(name)
        if path and path not in seen:
            seen.add(path)
            binaries.append(path)

    # Expand all search globs.
    for pattern in PHP_SEARCH_GLOBS:
        for path in sorted(glob_mod.glob(pattern)):
            real = os.path.realpath(path)
            if real not in seen and os.path.isfile(real) and os.access(real, os.X_OK):
                seen.add(real)
                binaries.append(real)

    return binaries


# ---------------------------------------------------------------------------
# PHP binary inspection
# ---------------------------------------------------------------------------

def php_version_of(binary: str) -> Optional[str]:
    """Get PHP_VERSION from a binary."""
    # Try CLI first.
    out = run_cmd([binary, "-r", "echo PHP_VERSION;"])
    if out:
        return out.strip()
    # FPM binaries: `php-fpm -v` prints "PHP x.y.z (fpm-fcgi) ...".
    out = run_cmd([binary, "-v"])
    if out:
        m = re.search(r"PHP (\d+\.\d+\.\d+\S*)", out)
        if m:
            return m.group(1)
    return None


def php_sapi_of(binary: str) -> Optional[str]:
    """Get PHP_SAPI from a binary."""
    out = run_cmd([binary, "-r", "echo PHP_SAPI;"])
    if out:
        return out.strip()
    if "fpm" in os.path.basename(binary):
        return "fpm"
    return None


def php_ini_value(binary: str, directive: str) -> Optional[str]:
    """Read an ini value from a PHP binary."""
    # CLI mode.
    out = run_cmd([binary, "-r", f"echo ini_get('{directive}');"])
    if out is not None:
        return out.strip()
    # FPM: try `php-fpm -i` and parse.
    out = run_cmd([binary, "-i"])
    if out:
        for line in out.splitlines():
            if line.startswith(directive):
                parts = line.split("=>")
                if len(parts) >= 2:
                    return parts[-1].strip()
    return None


def upload_progress_enabled(binary: str) -> Optional[bool]:
    """Check if session.upload_progress.enabled is On."""
    val = php_ini_value(binary, "session.upload_progress.enabled")
    if val is None:
        return None
    return val.lower() not in ("", "0", "off", "false", "no", "none")


def has_patch_marker(binary: str) -> Optional[bool]:
    """Check if the fix's INI directive (memory_hard_limit_percent) is registered.

    The fix commit registers a new INI directive in main/main.c.  If it appears
    in ``php -i`` output, the build contains the fix — regardless of what
    PHP_VERSION says.  This catches vendor backports that patch the binary
    without bumping the upstream version number.

    Returns True (directive present), False (directive absent from a complete
    ini dump), or None (could not determine).
    """
    out = run_cmd([binary, "-i"])
    if out is None:
        return None
    if PATCH_MARKER_DIRECTIVE in out:
        return True
    # Only return False (absent) if we got a substantial ini dump — otherwise
    # the binary might have failed to produce output and we shouldn't conclude
    # anything.  A real php -i dump is typically thousands of lines.
    if len(out) > 2000:
        return False
    return None


# ---------------------------------------------------------------------------
# Package manager: backport detection
# ---------------------------------------------------------------------------

def check_distro_backport(binary: str) -> Optional[Dict[str, Any]]:
    """Check if the PHP package owning this binary has backported CVE fixes.

    Returns a dict with 'found_cves' (list of matched CVE IDs) and
    'covers_both' (bool), or None if we can't determine.
    """
    changelog_text = _get_changelog_text(binary)
    if changelog_text is None:
        return None

    found = []
    if re.search(CVE_109618, changelog_text):
        found.append(CVE_109618)
    if re.search(CVE_109619, changelog_text):
        found.append(CVE_109619)

    if not found:
        return {"found_cves": [], "covers_both": False}

    return {
        "found_cves": found,
        "covers_both": len(found) == 2,
    }


def _get_changelog_text(binary: str) -> Optional[str]:
    """Extract changelog text for the package owning this binary."""
    # dpkg (Debian / Ubuntu)
    if which("dpkg"):
        out = run_cmd(["dpkg", "-S", binary])
        if out:
            pkg = out.split(":")[0].strip()
            if pkg:
                for changelog in [
                    f"/usr/share/doc/{pkg}/changelog.Debian.gz",
                    f"/usr/share/doc/{pkg.rsplit('-', 1)[0]}-common/changelog.Debian.gz",
                ]:
                    if os.path.exists(changelog):
                        content = run_cmd(["zcat", "-f", changelog])
                        if content:
                            return content
                return ""  # package found but no changelog content

    # rpm (RHEL / CentOS / Fedora)
    if which("rpm"):
        out = run_cmd(["rpm", "-qf", binary])
        if out:
            changelog = run_cmd(["rpm", "-q", "--changelog", out.strip()])
            if changelog:
                return changelog
            return ""

    return None


def get_package_info(binary: str) -> Optional[str]:
    """Get the package name and version that owns this binary."""
    if which("dpkg"):
        out = run_cmd(["dpkg", "-S", binary])
        if out:
            pkg = out.split(":")[0].strip()
            ver = run_cmd(["dpkg-query", "-W", "-f", "${Version}", pkg])
            if ver:
                return f"{pkg} {ver}"
            return pkg

    if which("rpm"):
        out = run_cmd(["rpm", "-qf", binary])
        if out:
            return out.strip()

    return None


# ---------------------------------------------------------------------------
# Docker container enumeration
# ---------------------------------------------------------------------------

def check_docker_containers() -> Tuple[List[Dict[str, Any]], List[str]]:
    """Check PHP in running Docker containers.

    Returns (assessed_containers, skipped_container_names).
    Containers without a reachable 'php' CLI binary are reported as skipped.
    """
    results = []
    skipped = []
    if not which("docker"):
        return results, skipped

    out = run_cmd(["docker", "ps", "--format", "{{.Names}}"])
    if not out:
        return results, skipped

    for name in out.splitlines():
        name = name.strip()
        if not name:
            continue
        ver_out = run_cmd([
            "docker", "exec", name, "php", "-r",
            "echo PHP_VERSION . '|' . PHP_SAPI . '|' "
            ". ini_get('session.upload_progress.enabled') . '|' "
            ". (ini_get('memory_hard_limit_percent') !== false ? 'marker_present' : 'marker_absent');"
        ], timeout=20)
        if not ver_out:
            skipped.append(name)
            continue
        parts = ver_out.split("|")
        if len(parts) >= 3:
            marker_val = parts[3].strip() if len(parts) >= 4 else ""
            results.append({
                "container": name,
                "php_version": parts[0],
                "sapi": parts[1],
                "upload_progress_enabled": parts[2].lower() not in ("", "0", "off", "false"),
                "patch_marker_present": True if marker_val == "marker_present" else
                                        (False if marker_val == "marker_absent" else None),
            })
        else:
            skipped.append(name)

    return results, skipped


# ---------------------------------------------------------------------------
# Held package detection
# ---------------------------------------------------------------------------

def check_held_packages() -> List[str]:
    """Detect PHP packages that are held/pinned and won't auto-update."""
    held = []

    if which("apt-mark"):
        out = run_cmd(["apt-mark", "showhold"])
        if out:
            held.extend(
                line.strip() for line in out.splitlines()
                if "php" in line.lower()
            )

    if which("dnf"):
        out = run_cmd(["dnf", "-q", "versionlock", "list"])
        if out:
            held.extend(
                line.strip() for line in out.splitlines()
                if "php" in line.lower()
            )
    elif which("yum"):
        out = run_cmd(["yum", "-q", "versionlock", "list"])
        if out:
            held.extend(
                line.strip() for line in out.splitlines()
                if "php" in line.lower()
            )

    return held


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------

def classify(
    version: Tuple[int, int, int],
    version_raw: str,
    upload_progress: Optional[bool],
    backport: Optional[Dict[str, Any]],
    patch_marker: Optional[bool] = None,
) -> Tuple[str, str, List[str]]:
    """Determine the verdict for a single PHP installation.

    Returns (verdict, confidence, [notes]).
    """
    branch = branch_of(version)
    notes: List[str] = []

    # Patch marker (memory_hard_limit_percent) is the strongest signal.
    # It's compiled into the binary by the fix commit itself, so it catches
    # vendor backports that don't change PHP_VERSION.
    if patch_marker is True:
        return (VERDICT_PATCHED, "high",
                [f"The fix's INI directive ({PATCH_MARKER_DIRECTIVE}) is registered "
                 f"in this build. The fix is present regardless of the version string "
                 f"({version_raw})."])
    if patch_marker is False:
        notes.append(f"The fix's INI directive ({PATCH_MARKER_DIRECTIVE}) is absent "
                     f"from php -i output, indicating the fix is not compiled into "
                     f"this build.")

    # Pre-5.4: upload_progress doesn't exist, CVE doesn't apply the same way.
    if version < UPLOAD_PROGRESS_SINCE:
        return (VERDICT_NOT_AFFECTED, "high",
                ["PHP version predates session.upload_progress (introduced in 5.4.0). "
                 "CVE-2026-109619 (multipart parser) may still apply — upgrade PHP."])

    # Check for backported fix in package changelog.
    if backport and backport.get("found_cves"):
        found = backport["found_cves"]
        covers_both = backport["covers_both"]

        # If patch_marker was False, we have a contradiction: the changelog
        # mentions the CVE but the directive is missing.  Trust the marker.
        if patch_marker is False:
            notes.append(
                f"Note: the package changelog references {', '.join(found)}, but "
                f"the {PATCH_MARKER_DIRECTIVE} directive is absent from the binary. "
                "The installed binary may not actually contain the fix.")
            # Fall through to version-based checks.
        else:
            backport_notes = [
                f"Distribution package changelog references: {', '.join(found)}."
            ]
            if not covers_both:
                missing = CVE_109619 if CVE_109618 in found else CVE_109618
                backport_notes.append(
                    f"Only {found[0]} was found in the changelog. {missing} is not "
                    f"explicitly mentioned. Assumption: the upstream fix addresses "
                    f"both CVEs in a single commit, so a backport for one likely "
                    f"covers both — but this has not been independently verified "
                    f"for this package.")
            else:
                backport_notes.append(
                    "Both CVEs are referenced. Verify the running binary matches "
                    "the installed package.")
            return (VERDICT_PATCHED, "high", backport_notes)

    # EOL branches.
    if branch in EOL_BRANCHES:
        if upload_progress is False:
            notes.append("EOL branch — no official patch will be released.")
            notes.append(
                "session.upload_progress.enabled is Off. This partially mitigates "
                f"{CVE_109619} by disabling the session upload-progress callback "
                "that is the primary demonstrated attack path for that CVE.")
            notes.append(
                f"{CVE_109618} (OOM corruption via multipart parsing) is NOT "
                "mitigated by this setting — the OOM path does not require "
                "upload-progress to be enabled.")
            notes.append("Upgrade to a supported PHP branch.")
            return (VERDICT_EOL_MITIGATED, "medium", notes)
        return (VERDICT_EOL_VULNERABLE, "high",
                notes + ["EOL branch — no official patch will be released. "
                         "Upgrade to a supported, patched PHP branch immediately."])

    # Supported branch: compare to fixed version.
    if branch in FIXED_BY_BRANCH:
        fixed = FIXED_BY_BRANCH[branch]

        # Check if version is at or above the fix.
        if version > fixed or (version == fixed and not is_prerelease(version_raw)):
            return (VERDICT_PATCHED, "high",
                    notes + [f"Version {version_str(version)} is at or above the fix "
                             f"({version_str(fixed)})."])

        if version == fixed and is_prerelease(version_raw):
            return (VERDICT_VULNERABLE, "high",
                    notes + [f"Prerelease of {version_str(fixed)} — the fix is in the "
                             f"release, not the prerelease."])

        # Version is below the fix.
        if upload_progress is False:
            notes.append(
                f"Version {version_str(version)} is below the fix "
                f"({version_str(fixed)}), but session.upload_progress.enabled "
                f"is Off.")
            notes.append(
                f"This partially mitigates {CVE_109619} by disabling the session "
                "upload-progress callback (the primary demonstrated attack path "
                "for that CVE). Other stale-state paths described in the advisory "
                "may still apply.")
            notes.append(
                f"{CVE_109618} (OOM corruption via multipart parsing) is NOT "
                "mitigated by this setting — the OOM path does not require "
                "upload-progress to be enabled.")
            notes.append("Upgrade PHP to fully address both CVEs.")
            return (VERDICT_MITIGATED, "medium", notes)

        notes.append(
            f"Version {version_str(version)} is below the fix "
            f"({version_str(fixed)}). Upgrade to {version_str(fixed)} or later.")
        return (VERDICT_VULNERABLE, "high", notes)

    # Branch not in our known-fixed map and not EOL — could be newer or unknown.
    if branch > (8, 5):
        return (VERDICT_UNKNOWN, "low",
                notes + [f"PHP {version_str(version)} is on a branch newer than 8.5 — "
                         f"check the vendor advisory for this branch."])

    return (VERDICT_UNKNOWN, "low",
            notes + [f"PHP {version_str(version)} is on an unrecognised branch. "
                     f"Cannot determine patch status."])


# ---------------------------------------------------------------------------
# Remediation text
# ---------------------------------------------------------------------------

def remediation_for(verdict: str, version: Optional[Tuple[int, int, int]]) -> str:
    if verdict == VERDICT_PATCHED:
        return ("Verify the running PHP worker matches the installed package. "
                "Confirm all workers were restarted after the update.")

    if verdict == VERDICT_VULNERABLE:
        if version and branch_of(version) in FIXED_BY_BRANCH:
            fixed = FIXED_BY_BRANCH[branch_of(version)]
            return (f"Upgrade to PHP {version_str(fixed)} or later and restart "
                    f"all PHP workers. Interim: set session.upload_progress.enabled = Off "
                    f"in php.ini and restart PHP (partial mitigation only).")
        return ("Upgrade to a patched PHP version and restart all PHP workers.")

    if verdict == VERDICT_MITIGATED:
        return ("session.upload_progress.enabled is Off, partially reducing "
                "exposure to CVE-2026-109619. CVE-2026-109618 (OOM corruption) "
                "is NOT mitigated by this setting. "
                "Upgrade PHP to a patched version as soon as possible.")

    if verdict in (VERDICT_EOL_VULNERABLE, VERDICT_EOL_MITIGATED):
        return ("This PHP branch is end-of-life and will not receive an official "
                "patch. Upgrade to a supported branch (8.2.35+, 8.3.36+, 8.4.27+, "
                "or 8.5.12+) immediately.")

    if verdict == VERDICT_NOT_AFFECTED:
        return "No immediate action for these specific CVEs, but upgrade PHP — this version is ancient."

    return "Manually verify PHP version, SAPI, and configuration."


# ---------------------------------------------------------------------------
# Main assessment
# ---------------------------------------------------------------------------

def assess_binary(binary: str) -> Dict[str, Any]:
    """Assess a single PHP binary."""
    version_raw = php_version_of(binary)
    sapi = php_sapi_of(binary)
    upload = upload_progress_enabled(binary)
    package = get_package_info(binary)
    marker = has_patch_marker(binary)
    is_tool = _is_build_tool(binary)

    result: Dict[str, Any] = {
        "binary": binary,
        "php_version": version_raw,
        "sapi": sapi,
        "package": package,
        "session_upload_progress_enabled": upload,
        "patch_marker_present": marker,
        "is_build_tool": is_tool,
    }

    if not version_raw:
        unknown_note = "Could not determine PHP version from this binary."
        if is_tool:
            unknown_note = (f"{os.path.basename(binary)} is a build/dev utility, "
                           "not a PHP runtime. Unable to assess — this does not "
                           "affect the verdict for actual PHP runtimes.")
        result["verdict"] = VERDICT_UNKNOWN
        result["confidence"] = "none"
        result["notes"] = [unknown_note]
        result["remediation"] = ("No action needed for build tools." if is_tool
                                 else "Manually inspect this binary.")
        return result

    version = parse_version(version_raw)
    if not version:
        result["verdict"] = VERDICT_UNKNOWN
        result["confidence"] = "none"
        result["notes"] = [f"Could not parse version string: {version_raw}"]
        result["remediation"] = "Manually inspect this binary."
        return result

    backport = check_distro_backport(binary)
    result["distro_backport_detected"] = backport

    verdict, confidence, notes = classify(
        version, version_raw, upload, backport, patch_marker=marker)
    result["verdict"] = verdict
    result["confidence"] = confidence
    result["notes"] = notes
    result["remediation"] = remediation_for(verdict, version)

    return result


def assess_container(container_info: Dict[str, Any]) -> Dict[str, Any]:
    """Assess a Docker container."""
    version_raw = container_info["php_version"]
    version = parse_version(version_raw)
    upload = container_info["upload_progress_enabled"]
    marker = container_info.get("patch_marker_present")

    result: Dict[str, Any] = {
        "source": "docker_container",
        "container": container_info["container"],
        "php_version": version_raw,
        "sapi": container_info.get("sapi"),
        "session_upload_progress_enabled": upload,
        "patch_marker_present": marker,
        "is_build_tool": False,
    }

    if not version:
        result["verdict"] = VERDICT_UNKNOWN
        result["confidence"] = "none"
        result["notes"] = [f"Could not parse version: {version_raw}"]
        result["remediation"] = "Manually inspect this container."
        return result

    verdict, confidence, notes = classify(
        version, version_raw, upload, None, patch_marker=marker)
    notes.append("Docker containers need a rebuilt image — host-level patching "
                 "does not apply inside the container.")
    result["verdict"] = verdict
    result["confidence"] = confidence
    result["notes"] = notes
    result["remediation"] = remediation_for(verdict, version)

    return result


def run_assessment(output_path: Optional[str] = None) -> Dict[str, Any]:
    """Run the full host assessment."""
    started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Discover and assess PHP binaries.
    binaries = discover_php_binaries()
    binary_results = [assess_binary(b) for b in binaries]

    # Check Docker containers.
    container_infos, skipped_containers = check_docker_containers()
    container_results = [assess_container(c) for c in container_infos]

    # Check for held packages.
    held = check_held_packages()

    # Overall verdict: worst-case across findings from actual runtimes.
    # Build tools (php-config, phpize, etc.) with UNKNOWN verdicts are
    # excluded from the rollup so they don't mask a definitive result.
    all_results = binary_results + container_results
    runtime_verdicts = [
        r["verdict"] for r in all_results
        if not r.get("is_build_tool", False)
    ]
    build_tool_unknowns = [
        r for r in all_results
        if r.get("is_build_tool", False) and r["verdict"] == VERDICT_UNKNOWN
    ]
    # Also include UNKNOWN from non-build-tool findings.
    runtime_unknowns = [
        r for r in all_results
        if not r.get("is_build_tool", False) and r["verdict"] == VERDICT_UNKNOWN
    ]

    if VERDICT_VULNERABLE in runtime_verdicts:
        overall = VERDICT_VULNERABLE
    elif VERDICT_EOL_VULNERABLE in runtime_verdicts:
        overall = VERDICT_EOL_VULNERABLE
    elif VERDICT_MITIGATED in runtime_verdicts:
        overall = VERDICT_MITIGATED
    elif VERDICT_EOL_MITIGATED in runtime_verdicts:
        overall = VERDICT_EOL_MITIGATED
    elif VERDICT_PATCHED in runtime_verdicts:
        overall = VERDICT_PATCHED
    elif VERDICT_NOT_AFFECTED in runtime_verdicts:
        overall = VERDICT_NOT_AFFECTED
    elif VERDICT_UNKNOWN in runtime_verdicts:
        overall = VERDICT_UNKNOWN
    elif not runtime_verdicts and not all_results:
        overall = VERDICT_UNKNOWN
    elif not runtime_verdicts and build_tool_unknowns:
        # Only build tools found, none of them are runtimes.
        overall = VERDICT_UNKNOWN
    else:
        overall = VERDICT_UNKNOWN

    finished = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Coverage limitations to include in the report.
    coverage_gaps: List[str] = []
    coverage_gaps.append(
        "This tool checks installed PHP binaries (CLI/FPM on disk). It does "
        "not verify which build is loaded by running Apache/FPM worker "
        "processes, or that workers were restarted after a package update.")
    if skipped_containers:
        coverage_gaps.append(
            f"Docker containers without an accessible PHP CLI binary were "
            f"skipped and could not be assessed: {', '.join(skipped_containers)}")
    if not os.geteuid() == 0:
        coverage_gaps.append(
            "Not running as root. Some PHP installations in restricted "
            "directories may not have been discovered.")

    # Safety block: accurate about what the tool did.
    files_modified = 1 if output_path else 0

    report: Dict[str, Any] = {
        "schema": "php2shell-host-check/v1",
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "started_at": started,
        "finished_at": finished,
        "hostname": platform.node(),
        "platform": platform.platform(),
        "running_as_root": os.geteuid() == 0,
        "relevant_cves": list(ADVISORIES.keys()),
        "official_advisories": ADVISORIES,
        "fixed_versions": {
            f"{major}.{minor}": version_str(fixed)
            for (major, minor), fixed in sorted(FIXED_BY_BRANCH.items())
        },
        "overall_verdict": overall,
        "php_binaries_found": len(binaries),
        "docker_containers_checked": len(container_infos),
        "docker_containers_skipped": skipped_containers,
        "held_packages": held,
        "findings": all_results,
        "coverage_gaps": coverage_gaps,
        "safety": {
            "network_requests_sent": 0,
            "files_modified": files_modified,
            "exploit_payloads_sent": 0,
            "description": (
                "Read-only host-local inspection. No network traffic, "
                "no exploit payloads."
                + (" One report file written via --output." if files_modified
                   else " No files modified.")
            ),
        },
    }

    if held:
        report["held_packages_warning"] = (
            "The following PHP packages are held/pinned and will NOT be "
            "auto-updated by the package manager. Manual intervention is "
            f"required: {', '.join(held)}"
        )

    return report


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

# Terminal colours (disabled when not a TTY).
if sys.stdout.isatty():
    _GREEN = "\033[0;32m"
    _YELLOW = "\033[1;33m"
    _RED = "\033[0;31m"
    _BOLD = "\033[1m"
    _RESET = "\033[0m"
else:
    _GREEN = _YELLOW = _RED = _BOLD = _RESET = ""


def _verdict_colour(verdict: str) -> str:
    if verdict in (VERDICT_PATCHED, VERDICT_NOT_AFFECTED):
        return _GREEN
    if verdict in (VERDICT_MITIGATED, VERDICT_EOL_MITIGATED, VERDICT_UNKNOWN):
        return _YELLOW
    return _RED


def print_human(report: Dict[str, Any]) -> None:
    """Print a human-readable summary."""
    print(f"\n{_BOLD}PHP2Shell Host Checker v{TOOL_VERSION}{_RESET}")
    print(f"CVE-2026-109618 / CVE-2026-109619")
    print("=" * 60)
    print(f"Host:      {report['hostname']}")
    print(f"Platform:  {report['platform']}")
    print(f"Root:      {'yes' if report['running_as_root'] else 'no (results may be incomplete)'}")
    print(f"Time:      {report['started_at']}")
    print()

    vc = _verdict_colour(report["overall_verdict"])
    print(f"Overall:   {vc}{_BOLD}{report['overall_verdict']}{_RESET}")
    print()

    if not report["findings"]:
        print("  No PHP binaries or containers found.")
        if not report["running_as_root"]:
            print("  Run as root for more complete coverage.")
        print()
        return

    print(f"{'Binary / Container':<50} {'Version':<12} {'SAPI':<10} "
          f"{'Upload Prog':<12} {'Fix Marker':<11} {'Verdict'}")
    print("-" * 121)

    for finding in report["findings"]:
        source = finding.get("container", finding.get("binary", "?"))
        # Truncate long paths.
        if len(source) > 48:
            source = "..." + source[-45:]

        ver = finding.get("php_version") or "?"
        sapi = finding.get("sapi") or "?"
        up = finding.get("session_upload_progress_enabled")
        up_str = "On" if up is True else ("Off" if up is False else "?")
        marker = finding.get("patch_marker_present")
        marker_str = "Yes" if marker is True else ("No" if marker is False else "?")
        verdict = finding["verdict"]
        vc = _verdict_colour(verdict)
        tool_tag = " [build tool]" if finding.get("is_build_tool") else ""

        print(f"  {source:<48} {ver:<12} {sapi:<10} {up_str:<12} "
              f"{marker_str:<11} {vc}{verdict}{_RESET}{tool_tag}")

        for note in finding.get("notes", []):
            print(f"    → {note}")

    print()

    # Coverage gaps.
    if report.get("coverage_gaps"):
        print(f"{_YELLOW}{_BOLD}Coverage limitations:{_RESET}")
        for gap in report["coverage_gaps"]:
            print(f"  • {gap}")
        print()

    if report.get("held_packages"):
        print(f"{_YELLOW}⚠ Held packages:{_RESET} {', '.join(report['held_packages'])}")
        print("  These will NOT auto-update. Manual intervention required.")
        print()

    # Print remediation summary.
    vuln_findings = [
        f for f in report["findings"]
        if f["verdict"] in (VERDICT_VULNERABLE, VERDICT_EOL_VULNERABLE)
    ]
    if vuln_findings:
        print(f"{_RED}{_BOLD}Remediation required:{_RESET}")
        print(f"  {vuln_findings[0]['remediation']}")
        print()
        print("  Fixed versions:")
        for branch, ver in sorted(FIXED_BY_BRANCH.items()):
            print(f"    PHP {branch[0]}.{branch[1]}: upgrade to {version_str(ver)}+")
        print()
        print("  Interim mitigation (partial — reduces CVE-2026-109619 exposure only):")
        print("    Set in php.ini:  session.upload_progress.enabled = Off")
        print("    Then restart PHP workers (systemctl restart php*-fpm, etc.)")
        print("    Note: CVE-2026-109618 (OOM corruption) is NOT mitigated by this setting.")
        print()
        print("  Reference:")
        for cve, url in ADVISORIES.items():
            print(f"    {cve}: {url}")
    elif report["overall_verdict"] == VERDICT_PATCHED:
        # Only say "all patched" if there are no runtime UNKNOWNs.
        runtime_unknowns = [
            f for f in report["findings"]
            if f["verdict"] == VERDICT_UNKNOWN and not f.get("is_build_tool")
        ]
        if runtime_unknowns:
            print(f"{_YELLOW}Assessed PHP runtimes appear patched, but "
                  f"{len(runtime_unknowns)} binary/container could not be "
                  f"fully assessed.{_RESET}")
            print("  Review the UNKNOWN findings above and verify manually.")
        else:
            print(f"{_GREEN}All detected PHP runtimes appear patched.{_RESET}")
            print("  Verify that all PHP workers were restarted after the update.")
    elif report["overall_verdict"] == VERDICT_MITIGATED:
        print(f"{_YELLOW}Partial mitigation is in place but PHP is not yet patched.{_RESET}")
        print("  session.upload_progress.enabled is Off (reduces CVE-2026-109619 exposure).")
        print("  CVE-2026-109618 (OOM corruption) is NOT mitigated by this setting.")
        print("  Upgrade PHP to a patched version as soon as possible.")

    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Host-local checker for CVE-2026-109618 / CVE-2026-109619 (PHP2Shell).",
        epilog=(
            "Run on the server you want to assess. Root recommended for full coverage.\n\n"
            "Exit codes:\n"
            "  0  All assessed runtimes are PATCHED or NOT_AFFECTED.\n"
            "  1  At least one finding is VULNERABLE, EOL_VULNERABLE, MITIGATED,\n"
            "     EOL_MITIGATED, or UNKNOWN. These do not confirm safety and should\n"
            "     not be treated as clean by automation.\n"
            "  2  Script error."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output structured JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--output", "-o", type=str, default=None,
        help="Write JSON report to this file path (implies --json).",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    args = parser.parse_args()

    use_json = args.json or args.output

    try:
        report = run_assessment(output_path=args.output)
    except Exception as exc:
        if use_json:
            print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        out_path = Path(args.output)
        if out_path.is_symlink():
            print(f"Error: refusing to write through symlink: {args.output}",
                  file=sys.stderr)
            return 2
        out_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"Report written to {args.output}")
    elif use_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_human(report)

    # Exit code: 0 only when every assessed runtime is PATCHED or NOT_AFFECTED.
    # MITIGATED and UNKNOWN return 1 because they do not confirm the absence
    # of exposure.
    safe_verdicts = {VERDICT_PATCHED, VERDICT_NOT_AFFECTED}
    runtime_findings = [
        f for f in report["findings"]
        if not f.get("is_build_tool", False)
    ]
    if not runtime_findings:
        return 1  # nothing assessed = not confirmed safe
    if all(f["verdict"] in safe_verdicts for f in runtime_findings):
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
