"""CLI logging must not be conflated with RSX3 telemetry collection."""

import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]

_PROBE = """
import sys
from reverse_socks.node import LOG, configure_logging
from reverse_socks.diagnostics import Metrics

enabled = sys.argv[2] == 'true'
configure_logging(sys.argv[1], diagnostics=enabled)
metrics = Metrics() if enabled else None
if metrics:
    LOG.addHandler(metrics)
try:
    LOG.debug('RSX3 metric slow_drain sid=7 drain_ms=120')
    LOG.info('RSX3 metric open_tcp sid=7 confirm_ms=460')
    LOG.info('RSX3 metric tcp_summary sid=7')
    LOG.warning('RSX3 connection rejected: bad token')
    LOG.error('RSX3 Diagnostics version mismatch')
    if metrics:
        records = list(metrics.logs)
        assert any('RSX3 metric open_tcp' in item for item in records)
        assert any('RSX3 metric slow_drain' in item for item in records)
        assert any('RSX3 Diagnostics version mismatch' in item for item in records)
finally:
    if metrics:
        LOG.removeHandler(metrics)
"""


class ConsoleLoggingTests(unittest.TestCase):
    def probe(self, level, diagnostics=False):
        return subprocess.run(
            [sys.executable, "-S", "-c", _PROBE,
             level, str(diagnostics).lower()],
            cwd=ROOT, capture_output=True, text=True, timeout=12,
            check=False,
        )

    def test_default_is_warning_and_diagnostics_off_does_not_print_metrics(self):
        from reverse_socks.node import parse_args
        args = parse_args([])
        self.assertEqual(args.log_level, "warning")
        self.assertFalse(args.diagnostics)
        result = self.probe(args.log_level)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("metric open_tcp", result.stderr)
        self.assertNotIn("metric tcp_summary", result.stderr)
        self.assertNotIn("metric slow_drain", result.stderr)
        self.assertIn("RSX3 connection rejected", result.stderr)
        self.assertIn("Diagnostics version mismatch", result.stderr)

    def test_info_prints_session_summary_but_not_debug_metrics(self):
        result = self.probe("info")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("metric open_tcp", result.stderr)
        self.assertIn("metric tcp_summary", result.stderr)
        self.assertNotIn("metric slow_drain", result.stderr)

    def test_debug_shows_detailed_performance_metrics(self):
        result = self.probe("debug")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("metric slow_drain", result.stderr)
        self.assertIn("metric tcp_summary", result.stderr)

    def test_error_prints_only_errors(self):
        result = self.probe("error")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("metric", result.stderr)
        self.assertNotIn("connection rejected", result.stderr)
        self.assertIn("Diagnostics version mismatch", result.stderr)

    def test_diagnostics_retains_raw_logs_at_warning_console_level(self):
        result = self.probe("warning", diagnostics=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("metric open_tcp", result.stderr)
        self.assertNotIn("metric slow_drain", result.stderr)
        self.assertIn("connection rejected", result.stderr)

    def test_cli_levels_are_strict_but_case_insensitive(self):
        from reverse_socks.node import parse_args
        self.assertEqual(parse_args(["--log-level", "INFO"]).log_level, "info")
        result = subprocess.run(
            [sys.executable, "-S", "-m", "reverse_socks",
             "--log-level", "noisy", "--print-diagnostics-config"],
            cwd=ROOT, capture_output=True, text=True, timeout=12,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr)

    def test_cli_print_diagnostics_configuration_has_no_extra_logging(self):
        env = dict(os.environ, REVERSE_SOCKS_TOKEN="test-logging-token-min-16-characters")
        result = subprocess.run(
            [sys.executable, "-S", "-m", "reverse_socks",
             "--print-diagnostics-config", "--log-level", "warning"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=12,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.strip().splitlines()), 3)
        self.assertEqual(result.stderr, "")

    def test_missing_token_stays_a_clear_cli_error(self):
        env = dict(os.environ)
        env.pop("REVERSE_SOCKS_TOKEN", None)
        result = subprocess.run(
            [sys.executable, "-S", "-m", "reverse_socks", "--log-level", "warning"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=12,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("set REVERSE_SOCKS_TOKEN", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_non_loopback_udp_stays_a_clear_cli_error(self):
        env = dict(os.environ, REVERSE_SOCKS_TOKEN="test-logging-token-min-16-characters")
        result = subprocess.run(
            [sys.executable, "-S", "-m", "reverse_socks",
             "--udp-bind", "0.0.0.0:9314", "--log-level", "warning"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=12,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UDP endpoints must be 127.0.0.1", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
