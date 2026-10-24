#!/usr/bin/env python3
"""Unit tests for the classify() verdict logic in php2shell_local_checker.py.

These test the decision logic directly with synthetic inputs, covering the
regression cases from code review feedback.  No Docker, no network, no PHP
binaries needed — just Python 3.6+.

Usage:
    python3 tests_classify.py
    python3 tests_classify.py -v     # verbose
"""
import sys
import unittest

# Import from the checker script in the same directory.
sys.path.insert(0, ".")
from php2shell_local_checker import (
    classify,
    VERDICT_PATCHED,
    VERDICT_VULNERABLE,
    VERDICT_MITIGATED,
    VERDICT_EOL_VULNERABLE,
    VERDICT_EOL_MITIGATED,
    VERDICT_NOT_AFFECTED,
    VERDICT_UNKNOWN,
)


class TestOverallVerdictPriority(unittest.TestCase):
    """Test that the overall verdict rollup handles combinations correctly.

    These simulate the runtime_verdicts list that run_assessment() builds,
    testing the priority logic without needing real containers.
    """

    def _overall(self, runtime_verdicts):
        """Simulate the overall verdict rollup logic from run_assessment()."""
        if VERDICT_VULNERABLE in runtime_verdicts:
            return VERDICT_VULNERABLE
        elif VERDICT_EOL_VULNERABLE in runtime_verdicts:
            return VERDICT_EOL_VULNERABLE
        elif VERDICT_MITIGATED in runtime_verdicts:
            return VERDICT_MITIGATED
        elif VERDICT_EOL_MITIGATED in runtime_verdicts:
            return VERDICT_EOL_MITIGATED
        elif VERDICT_UNKNOWN in runtime_verdicts:
            return VERDICT_UNKNOWN
        elif VERDICT_PATCHED in runtime_verdicts:
            return VERDICT_PATCHED
        elif VERDICT_NOT_AFFECTED in runtime_verdicts:
            return VERDICT_NOT_AFFECTED
        else:
            return VERDICT_UNKNOWN

    def test_patched_plus_runtime_unknown_is_unknown(self):
        """PATCHED + genuine runtime UNKNOWN → UNKNOWN."""
        result = self._overall([VERDICT_PATCHED, VERDICT_UNKNOWN])
        self.assertEqual(result, VERDICT_UNKNOWN)

    def test_not_affected_plus_runtime_unknown_is_unknown(self):
        """NOT_AFFECTED + genuine runtime UNKNOWN → UNKNOWN."""
        result = self._overall([VERDICT_NOT_AFFECTED, VERDICT_UNKNOWN])
        self.assertEqual(result, VERDICT_UNKNOWN)

    def test_vulnerable_plus_unknown_is_vulnerable(self):
        """VULNERABLE + UNKNOWN → VULNERABLE (vuln takes priority)."""
        result = self._overall([VERDICT_VULNERABLE, VERDICT_UNKNOWN])
        self.assertEqual(result, VERDICT_VULNERABLE)

    def test_patched_only_is_patched(self):
        """PATCHED alone (no UNKNOWN) → PATCHED."""
        result = self._overall([VERDICT_PATCHED])
        self.assertEqual(result, VERDICT_PATCHED)

    def test_no_runtimes_is_unknown(self):
        """No assessed runtimes → UNKNOWN."""
        result = self._overall([])
        self.assertEqual(result, VERDICT_UNKNOWN)

    def test_patched_plus_patched_is_patched(self):
        """Multiple PATCHED → PATCHED."""
        result = self._overall([VERDICT_PATCHED, VERDICT_PATCHED])
        self.assertEqual(result, VERDICT_PATCHED)

    def test_eol_vulnerable_plus_unknown_is_eol_vulnerable(self):
        """EOL_VULNERABLE + UNKNOWN → EOL_VULNERABLE."""
        result = self._overall([VERDICT_EOL_VULNERABLE, VERDICT_UNKNOWN])
        self.assertEqual(result, VERDICT_EOL_VULNERABLE)


class TestClassifyBackportChangelog(unittest.TestCase):
    """Changelog mentions should be evidence, not confirmation."""

    def test_one_cve_in_changelog_marker_unavailable_old_version(self):
        """Older PHP, marker unavailable, one CVE mentioned → UNKNOWN / low."""
        backport = {"found_cves": ["CVE-2026-109618"], "covers_both": False}
        verdict, confidence, notes = classify(
            version=(8, 2, 30),
            version_raw="8.2.30",
            upload_progress=True,
            backport=backport,
            patch_marker=None,  # marker couldn't be checked
        )
        self.assertEqual(verdict, VERDICT_UNKNOWN)
        self.assertEqual(confidence, "low")

    def test_both_cves_in_changelog_marker_unavailable_old_version(self):
        """Older PHP, marker unavailable, both CVEs mentioned → UNKNOWN / low."""
        backport = {
            "found_cves": ["CVE-2026-109618", "CVE-2026-109619"],
            "covers_both": True,
        }
        verdict, confidence, notes = classify(
            version=(8, 2, 30),
            version_raw="8.2.30",
            upload_progress=True,
            backport=backport,
            patch_marker=None,
        )
        self.assertEqual(verdict, VERDICT_UNKNOWN)
        self.assertEqual(confidence, "low")

    def test_changelog_mentions_but_marker_absent_upload_on(self):
        """Older PHP, marker absent, upload progress enabled → VULNERABLE
        despite changelog mentions."""
        backport = {
            "found_cves": ["CVE-2026-109618", "CVE-2026-109619"],
            "covers_both": True,
        }
        verdict, confidence, notes = classify(
            version=(8, 2, 30),
            version_raw="8.2.30",
            upload_progress=True,
            backport=backport,
            patch_marker=False,  # marker explicitly absent
        )
        self.assertEqual(verdict, VERDICT_VULNERABLE)
        self.assertEqual(confidence, "high")

    def test_changelog_with_marker_present_is_patched(self):
        """Changelog + marker present → still PATCHED (marker is the authority)."""
        backport = {"found_cves": ["CVE-2026-109618"], "covers_both": False}
        verdict, confidence, notes = classify(
            version=(8, 2, 30),
            version_raw="8.2.30",
            upload_progress=True,
            backport=backport,
            patch_marker=True,
        )
        self.assertEqual(verdict, VERDICT_PATCHED)
        self.assertEqual(confidence, "high")


class TestClassifyVersionMarkerConflict(unittest.TestCase):
    """Fixed-version PHP with marker explicitly absent → UNKNOWN."""

    def test_fixed_version_marker_absent(self):
        """PHP 8.4.27 (at fix) but marker absent → UNKNOWN / low."""
        verdict, confidence, notes = classify(
            version=(8, 4, 27),
            version_raw="8.4.27",
            upload_progress=True,
            backport=None,
            patch_marker=False,
        )
        self.assertEqual(verdict, VERDICT_UNKNOWN)
        self.assertEqual(confidence, "low")
        self.assertTrue(any("conflicting evidence" in n for n in notes))

    def test_above_fixed_version_marker_absent(self):
        """PHP 8.4.28 (above fix) but marker absent → UNKNOWN / low."""
        verdict, confidence, notes = classify(
            version=(8, 4, 28),
            version_raw="8.4.28",
            upload_progress=True,
            backport=None,
            patch_marker=False,
        )
        self.assertEqual(verdict, VERDICT_UNKNOWN)
        self.assertEqual(confidence, "low")

    def test_fixed_version_marker_present(self):
        """PHP 8.4.27 + marker present → PATCHED (normal case)."""
        verdict, confidence, notes = classify(
            version=(8, 4, 27),
            version_raw="8.4.27",
            upload_progress=True,
            backport=None,
            patch_marker=True,
        )
        self.assertEqual(verdict, VERDICT_PATCHED)
        self.assertEqual(confidence, "high")

    def test_fixed_version_marker_unknown(self):
        """PHP 8.4.27 + marker unknown → PATCHED (version alone sufficient
        when marker is inconclusive)."""
        verdict, confidence, notes = classify(
            version=(8, 4, 27),
            version_raw="8.4.27",
            upload_progress=True,
            backport=None,
            patch_marker=None,
        )
        self.assertEqual(verdict, VERDICT_PATCHED)
        self.assertEqual(confidence, "high")


class TestClassifyExistingVerdicts(unittest.TestCase):
    """Ensure existing verdict paths still work correctly."""

    def test_vulnerable_below_fix(self):
        verdict, confidence, _ = classify(
            (8, 4, 4), "8.4.4", True, None, patch_marker=False)
        self.assertEqual(verdict, VERDICT_VULNERABLE)

    def test_eol_vulnerable(self):
        verdict, confidence, _ = classify(
            (7, 4, 33), "7.4.33", True, None, patch_marker=False)
        self.assertEqual(verdict, VERDICT_EOL_VULNERABLE)

    def test_mitigated_upload_off(self):
        verdict, confidence, _ = classify(
            (8, 4, 4), "8.4.4", False, None, patch_marker=False)
        self.assertEqual(verdict, VERDICT_MITIGATED)

    def test_eol_mitigated(self):
        verdict, confidence, _ = classify(
            (7, 4, 33), "7.4.33", False, None, patch_marker=False)
        self.assertEqual(verdict, VERDICT_EOL_MITIGATED)

    def test_patched_by_marker(self):
        verdict, confidence, _ = classify(
            (8, 2, 30), "8.2.30", True, None, patch_marker=True)
        self.assertEqual(verdict, VERDICT_PATCHED)

    def test_pre_5_4_not_affected(self):
        verdict, confidence, _ = classify(
            (5, 3, 29), "5.3.29", None, None, patch_marker=None)
        self.assertEqual(verdict, VERDICT_NOT_AFFECTED)

    def test_prerelease_of_fix_is_vulnerable(self):
        verdict, confidence, _ = classify(
            (8, 4, 27), "8.4.27-RC1", True, None, patch_marker=False)
        self.assertEqual(verdict, VERDICT_VULNERABLE)


class TestExitCodes(unittest.TestCase):
    """Exit code 0 should only be returned for fully safe results."""

    def _simulate_exit(self, runtime_verdicts):
        """Simulate the exit code logic from main()."""
        safe = {VERDICT_PATCHED, VERDICT_NOT_AFFECTED}
        if not runtime_verdicts:
            return 1
        if all(v in safe for v in runtime_verdicts):
            return 0
        return 1

    def test_patched_exits_0(self):
        self.assertEqual(self._simulate_exit([VERDICT_PATCHED]), 0)

    def test_not_affected_exits_0(self):
        self.assertEqual(self._simulate_exit([VERDICT_NOT_AFFECTED]), 0)

    def test_vulnerable_exits_1(self):
        self.assertEqual(self._simulate_exit([VERDICT_VULNERABLE]), 1)

    def test_mitigated_exits_1(self):
        self.assertEqual(self._simulate_exit([VERDICT_MITIGATED]), 1)

    def test_unknown_exits_1(self):
        self.assertEqual(self._simulate_exit([VERDICT_UNKNOWN]), 1)

    def test_eol_vulnerable_exits_1(self):
        self.assertEqual(self._simulate_exit([VERDICT_EOL_VULNERABLE]), 1)

    def test_no_runtimes_exits_1(self):
        self.assertEqual(self._simulate_exit([]), 1)

    def test_patched_plus_unknown_exits_1(self):
        self.assertEqual(self._simulate_exit([VERDICT_PATCHED, VERDICT_UNKNOWN]), 1)


if __name__ == "__main__":
    unittest.main()
