import tempfile
import unittest
from pathlib import Path

from pettachainer.benchmarks.smart_dispatch import run_benchmark


class TestSmartDispatchBenchmark(unittest.TestCase):
    def test_dispatch_codegen_and_timing_order(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_benchmark(
                iterations=8_000,
                repeats=2,
                trace_path=Path(tmpdir) / "smart-dispatch.log",
            )

        self.assertTrue(all(result.checks.values()), result.checks)
        timings = {timing.name: timing for timing in result.timings}
        self.assertEqual(timings["smart"].output, ["8000"])
        self.assertEqual(timings["smart"].codegen_marker, "direct_predicate_call")
        self.assertEqual(timings["call"].codegen_marker, "direct_predicate_call")
        self.assertEqual(timings["reduce"].codegen_marker, "dynamic_reduce")
        self.assertEqual(timings["eval"].codegen_marker, "runtime_eval")
        self.assertGreater(timings["reduce"].ratio_to_smart, 1.0)
        self.assertGreater(timings["eval"].ratio_to_smart, timings["reduce"].ratio_to_smart)


if __name__ == "__main__":
    unittest.main()
