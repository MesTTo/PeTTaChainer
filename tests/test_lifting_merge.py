import random
import unittest

from pettachainer import PeTTaChainer

ROUNDTRIP_DEFINITION = """
(= (lifting-fuzz-roundtrip $antecedent $positive $negative)
   (lifting-tv-close?
      (TotalMpFormula $antecedent $positive $negative)
      (lifting-apply-residual
         $antecedent
         (total-mp-residual
            (TotalMpFormula (STV 1.0 1.0) $positive $negative)
            (TotalMpFormula (STV 0.0 1.0) $positive $negative)))))
"""


class TestLiftingMergeProperties(unittest.TestCase):
    def test_total_mp_residual_roundtrip_fuzz(self):
        handler = PeTTaChainer()
        self.assertEqual(handler.handler.process_metta_string(ROUNDTRIP_DEFINITION), [])

        boundary_values = (0.0, 0.0001, 0.1, 0.5, 0.9, 0.9999, 1.0)
        cases = [
            (a_s, a_c, p_s, p_c, n_s, n_c)
            for a_s, a_c, p_s, p_c, n_s, n_c in zip(
                boundary_values,
                reversed(boundary_values),
                boundary_values,
                boundary_values[1:] + boundary_values[:1],
                reversed(boundary_values),
                boundary_values[2:] + boundary_values[:2],
            )
        ]

        random_values = random.Random(0x5EED)
        cases.extend(
            tuple(random_values.random() for _ in range(6)) for _ in range(200)
        )

        for case in cases:
            a_s, a_c, p_s, p_c, n_s, n_c = case
            expression = (
                "!(lifting-fuzz-roundtrip "
                f"(STV {a_s:.17g} {a_c:.17g}) "
                f"(STV {p_s:.17g} {p_c:.17g}) "
                f"(STV {n_s:.17g} {n_c:.17g}))"
            )
            with self.subTest(case=case):
                self.assertEqual(
                    handler.handler.process_metta_string(expression), ["true"]
                )


if __name__ == "__main__":
    unittest.main()
