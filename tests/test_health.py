"""Offline health log tests. No GitHub credentials or network needed."""
import unittest

from security_radar.health import append_history, github_run_url, record_run, summarize_sources


class HealthTests(unittest.TestCase):
    def test_source_snapshot_and_results(self):
        sources = {
            "github_advisories": {"state": "error", "count": 31,
                                  "error_type": "pagination", "error": "Repeated cursor",
                                  "last_success": "2026-11-16T08:00:00Z",
                                  "consecutive_failures": 2},
            "nist_nvd": {"state": "ok", "count": 15,
                         "last_success": "2026-11-17T08:00:00Z"},
        }
        status = {"partial": True, "sources": sources, "source_errors": ["github_advisories"],
                  "stored_records": 414, "new_relevant_alerts": 1}
        entry = record_run(status, started_at="2026-11-17T07:59:00Z",
                           finished_at="2026-11-17T08:00:00Z",
                           duration_seconds=60.27,
                           run_url="https://github.com/gu-ma/security-radar/actions/runs/123")
        self.assertEqual(entry["result"], "degraded")
        self.assertEqual(entry["duration_seconds"], 60.27)
        self.assertEqual(entry["sources"]["github_advisories"]["error_type"], "pagination")
        self.assertEqual(entry["sources"]["nist_nvd"]["count"], 15)

    def test_failed_and_healthy(self):
        args = {"started_at": "2026-11-17T00:00:00Z",
                "finished_at": "2026-11-17T00:01:00Z"}
        self.assertEqual(record_run({"failed": True, "partial": True}, **args)["result"], "failed")
        self.assertEqual(record_run({"partial": False}, **args)["result"], "healthy")

    def test_history_is_bounded_and_no_duplicates(self):
        history = []
        for n in range(90):
            entry = {"finished_at": f"2026-11-{n + 1:02d}T00:00:00Z", "run_url": str(n)}
            history = append_history(history, entry)
        self.assertEqual(len(history), 40)
        newest = history[0]
        history = append_history(history, newest)
        self.assertEqual(len(history), 40)
        self.assertEqual(sum(item["run_url"] == newest["run_url"] for item in history), 1)
        self.assertEqual(append_history({}, newest), [newest])

    def test_run_url_validation(self):
        self.assertEqual(github_run_url({"GITHUB_RUN_ID": "42",
            "GITHUB_REPOSITORY": "gu-ma/security-radar"}),
            "https://github.com/gu-ma/security-radar/actions/runs/42")
        self.assertEqual(github_run_url({"GITHUB_RUN_ID": "bad",
            "GITHUB_REPOSITORY": "gu-ma/security-radar"}), "")
        self.assertEqual(github_run_url({"GITHUB_RUN_ID": "42",
            "GITHUB_REPOSITORY": "evil.example/path"}), "https://github.com/evil.example/path/actions/runs/42")
        # The link cannot be used to target a different origin.

    def test_no_response_bodies_in_health_summary(self):
        data = {"source": {"state": "error", "error": "X" * 10000}}
        self.assertLessEqual(len(summarize_sources(data)["source"]["error"]), 260)


if __name__ == "__main__":
    unittest.main()
