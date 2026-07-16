import inspect
import random
import unittest

from pettachainer import PeTTaChainer


class TestPeTTaChainer(unittest.TestCase):
    def test_removed_pattern_mining_api_is_absent(self):
        removed_methods = (
            "set_pattern_mining_on_add",
            "enable_pattern_mining_on_add",
            "disable_pattern_mining_on_add",
            "materialize_mined_implications",
        )
        for method in removed_methods:
            with self.subTest(method=method):
                self.assertFalse(hasattr(PeTTaChainer, method))

        self.assertNotIn("mine_patterns", inspect.signature(PeTTaChainer.add_atom).parameters)
        self.assertNotIn(
            "mine_patterns", inspect.signature(PeTTaChainer.add_atoms_no_check).parameters
        )

        handler = PeTTaChainer()
        self.assertEqual(
            handler.handler.process_metta_string("!(get-metatype compileadd)"), ["Grounded"]
        )
        removed_symbols = (
            "compileadd-mine",
            "set-pattern-mining-on-add",
            "enable-pattern-mining-on-add",
            "disable-pattern-mining-on-add",
            "materialize-mined-implications",
        )
        for symbol in removed_symbols:
            with self.subTest(symbol=symbol):
                metatype = handler.handler.process_metta_string(f"!(get-metatype {symbol})")
                self.assertEqual(metatype, ["Symbol"])

    def test_forward_chain_derives_fact_visible_to_backward_query(self):
        handler = PeTTaChainer()
        handler.add_atom("(: edge_ab (Edge A B) (STV 1.0 1.0))")
        handler.add_atom("(: edge_bc (Edge B C) (STV 1.0 1.0))")
        handler.add_atom(
            "(: edge_to_path (Implication (Premises (Edge $x $y)) (Conclusions (Path $x $y))) (STV 1.0 1.0))"
        )
        handler.add_atom(
            "(: path_step (Implication (Premises (Path $x $y) (Edge $y $z)) (Conclusions (Path $x $z))) (STV 1.0 1.0))"
        )

        result = handler.forward_chain(steps=50)

        self.assertIn("true", str(result))
        proofs = handler.query("(: $prf (Path A C) $tv)", steps=10, timeout_sec=0)
        self.assertTrue(proofs)

    def test_forward_chain_can_start_from_selected_term(self):
        handler = PeTTaChainer()
        handler.add_atom("(: high_fact (HighPriority) (STV 1.0 1.0))")
        handler.add_atom("(: low_fact (LowPriority) (STV 1.0 0.8))")
        handler.add_atom(
            "(: low_to_goal (Implication (Premises (LowPriority)) (Conclusions (DeltaGoal))) (STV 1.0 1.0))"
        )

        result = handler.forward_chain(steps=1, term="(LowPriority)")

        self.assertIn("true", str(result))
        proofs = handler.query("(: $prf (DeltaGoal) $tv)", steps=10, timeout_sec=0)
        self.assertTrue(proofs)

    def test_forward_chain_can_start_from_selected_facts(self):
        handler = PeTTaChainer()
        handler.add_atom("(: high_fact (HighPriority) (STV 1.0 1.0))")
        handler.add_atom("(: low_fact (LowPriority) (STV 1.0 0.8))")
        handler.add_atom(
            "(: low_to_goal (Implication (Premises (LowPriority)) (Conclusions (FactSeedGoal))) (STV 1.0 1.0))"
        )

        result = handler.forward_chain_from_facts(["(LowPriority)"], steps=1)

        self.assertIn("true", str(result))
        proofs = handler.query("(: $prf (FactSeedGoal) $tv)", steps=10, timeout_sec=0)
        self.assertTrue(proofs)

    def test_forward_chain_sequence_term_uses_selected_facts(self):
        handler = PeTTaChainer()
        handler.add_atom("(: high_fact (HighPriority) (STV 1.0 1.0))")
        handler.add_atom("(: low_fact (LowPriority) (STV 1.0 0.8))")
        handler.add_atom(
            "(: low_to_goal (Implication (Premises (LowPriority)) (Conclusions (FactSeedGoal2))) (STV 1.0 1.0))"
        )

        result = handler.forward_chain(steps=1, term=["(LowPriority)"])

        self.assertIn("true", str(result))
        proofs = handler.query("(: $prf (FactSeedGoal2) $tv)", steps=10, timeout_sec=0)
        self.assertTrue(proofs)

    def test_forward_chain_from_facts_returns_false_for_missing_seed(self):
        handler = PeTTaChainer()

        result = handler.forward_chain_from_facts(["(MissingSeed)"], steps=1)

        self.assertEqual(result, ["false"])

    def test_backward_premise_prefilter_is_kb_scoped_and_reaches_timeout_worker(self):
        handler = PeTTaChainer()
        other = PeTTaChainer()
        handler.add_atoms_no_check(
            ["(: filter_live (FilterInput live) (STV 1.0 1.0))"]
            + [
                "(: filter_live_rule "
                "(Implication (Premises (FilterInput live)) (Conclusions (FilterOutput))) "
                "(STV 1.0 0.2))"
            ]
            + [
                f"(: (no_inverse filter_dead_{index}) "
                f"(Implication (Premises (FilterInput dead-{index})) "
                "(Conclusions (FilterOutput))) (STV 1.0 1.0))"
                for index in range(8)
            ]
        )

        handler.set_backward_premise_prefilter(False)
        self.assertFalse(handler.query("(: $prf (FilterOutput) $tv)", steps=4, timeout_sec=0))

        handler.set_backward_premise_prefilter(True)
        self.assertTrue(handler.query("(: $prf (FilterOutput) $tv)", steps=4, timeout_sec=0))
        self.assertTrue(handler.query("(: $prf (FilterOutput) $tv)", steps=4, timeout_sec=5))
        self.assertEqual(
            handler.handler.process_metta_string(
                f"!(backward-premise-prefilter? ((Probe) ({handler.kb} MAIN Nil) $proof $tv))"
            ),
            ["true"],
        )
        self.assertEqual(
            other.handler.process_metta_string(
                f"!(backward-premise-prefilter? ((Probe) ({other.kb} MAIN Nil) $proof $tv))"
            ),
            ["false"],
        )
        with self.assertRaisesRegex(TypeError, "bool"):
            handler.set_backward_premise_prefilter(1)

    def test_backward_premise_prefilter_randomized_answer_equivalence(self):
        rng = random.Random(20260718)
        handler = PeTTaChainer()
        item_count = 12
        present = {index for index in range(item_count) if rng.random() < 0.6}
        handler.add_atoms_no_check(
            [
                f"(: filter_base_{index} (FilterBase {index}) (STV 1.0 1.0))"
                for index in sorted(present)
            ]
            + [
                f"(: (no_inverse filter_middle_{index}) "
                f"(Implication (Premises (FilterBase {index})) "
                f"(Conclusions (FilterMiddle {index}))) (STV 1.0 0.9))"
                for index in range(item_count)
            ]
            + [
                f"(: (no_inverse filter_goal_{index}) "
                f"(Implication (Premises (FilterMiddle {index})) "
                f"(Conclusions (FilterGoal {index}))) (STV 1.0 0.8))"
                for index in range(item_count)
            ]
        )

        handler.set_backward_premise_prefilter(False)
        without_filter = [
            set(handler.query(f"(: $prf (FilterGoal {index}) $tv)", steps=50, timeout_sec=0))
            for index in range(item_count)
        ]
        handler.set_backward_premise_prefilter(True)
        with_filter = [
            set(handler.query(f"(: $prf (FilterGoal {index}) $tv)", steps=50, timeout_sec=0))
            for index in range(item_count)
        ]

        self.assertEqual(with_filter, without_filter)
        self.assertEqual(
            [bool(answers) for answers in with_filter],
            [index in present for index in range(item_count)],
        )

    def test_default_logic_keeps_pln_or_semantics(self):
        handler = PeTTaChainer()
        handler.add_atom("(: a (A) (STV 1.0 1.0))")

        proofs = handler.query("(: $prf (Or (A) (B)) $tv)", steps=20)

        self.assertEqual(proofs, [])

    def test_predicate_logic_config_or_introduction(self):
        handler = PeTTaChainer(logic_config="predicate_logic")
        handler.add_atom("(: a (A) (STV 1.0 1.0))")

        proofs = handler.query("(: $prf (Or (A) (B)) $tv)", steps=20, timeout_sec=0)

        self.assertTrue(proofs)

    def test_contextual_query_projects_generated_exception_context(self):
        handler = PeTTaChainer()
        handler.add_atoms_no_check(
            [
                "(: bird_robin (Bird robin) (STV 1.0 0.99))",
                "(: bird_polly (Bird polly) (STV 1.0 0.99))",
                "(: bird_tweety (Bird tweety) (STV 1.0 0.99))",
                "(: penguin_polly (Penguin polly) (STV 1.0 0.99))",
                "(: penguin_tweety (Penguin tweety) (STV 1.0 0.99))",
                "(: fly_robin (Fly robin) (STV 0.95 0.99))",
                "(: fly_polly (Fly polly) (STV 0.0 0.99))",
                "(: bird_to_fly (Implication (Premises (Bird $x)) (Conclusions (Fly $x))) (STV 0.95 0.99))",
            ]
        )

        result = handler.contextual_query("(: $prf (Fly tweety) $tv)", steps=20, timeout_sec=0)

        self.assertIsInstance(result.proofs, tuple)
        self.assertIsNotNone(result.projection)
        self.assertIn("(Fly tweety)", result.projection)
        self.assertIn("(STV 0", result.projection)
        self.assertEqual(result.answers[0], result.projection)

    def test_remove_statement_rebuilds_replay_state(self):
        handler = PeTTaChainer()
        handler.add_atoms_no_check(
            [
                "(: remove_seed (RemoveSeed) (STV 1.0 1.0))",
                "(: keep_seed (KeepSeed) (STV 1.0 1.0))",
                "(: remove_rule (Implication (Premises (RemoveSeed)) (Conclusions (RemovedGoal))) (STV 1.0 1.0))",
                "(: keep_rule (Implication (Premises (KeepSeed)) (Conclusions (KeptGoal))) (STV 1.0 1.0))",
            ]
        )

        self.assertTrue(handler.query("(: $prf (RemovedGoal) $tv)", timeout_sec=0))
        self.assertEqual(handler.remove_statement("remove_seed"), 1)
        self.assertFalse(handler.query("(: $prf (RemovedGoal) $tv)", timeout_sec=0))
        self.assertTrue(handler.query("(: $prf (KeptGoal) $tv)", timeout_sec=0))
        self.assertFalse(any("remove_seed" in atom for atom in handler._added_atoms))
        self.assertFalse(handler.query("(: $prf (RemovedGoal) $tv)", timeout_sec=5))
        self.assertTrue(handler.query("(: $prf (KeptGoal) $tv)", timeout_sec=5))

    def test_remove_statement_handles_duplicates_wrappers_and_kb_scope(self):
        left = PeTTaChainer()
        right = PeTTaChainer()
        left.add_atoms_no_check(
            [
                "(: duplicate_name (DuplicateOne) (STV 1.0 1.0))",
                "(: duplicate_name (DuplicateTwo) (STV 1.0 1.0))",
                "(: wrapped_seed (WrappedSeed) (STV 1.0 1.0))",
                "(: (no_inverse wrapped_rule) (Implication (Premises (WrappedSeed)) (Conclusions (WrappedGoal))) (STV 1.0 1.0))",
            ]
        )
        right.add_atom("(: duplicate_name (RightDuplicate) (STV 1.0 1.0))")

        self.assertEqual(left.remove_statement("duplicate_name"), 2)
        self.assertFalse(left.query("(: $prf (DuplicateOne) $tv)", timeout_sec=0))
        self.assertFalse(left.query("(: $prf (DuplicateTwo) $tv)", timeout_sec=0))
        self.assertTrue(right.query("(: $prf (RightDuplicate) $tv)", timeout_sec=0))
        self.assertEqual(left.remove_statement("(no_inverse wrapped_rule)"), 1)
        self.assertFalse(left.query("(: $prf (WrappedGoal) $tv)", timeout_sec=0))
        self.assertEqual(left.remove_statement("missing_name"), 0)

    def test_remove_statement_rejects_variable_names(self):
        handler = PeTTaChainer()

        with self.assertRaisesRegex(ValueError, "ground"):
            handler.remove_statement("$name")

    def test_remove_statement_randomized_rebuild_property(self):
        rng = random.Random(20260717)
        handler = PeTTaChainer()
        item_count = 16
        handler.add_atoms_no_check(
            [
                f"(: fuzz_fact_{index} (FuzzFact {index}) (STV 1.0 1.0))"
                for index in range(item_count)
            ]
            + [
                f"(: fuzz_rule_{index} (Implication (Premises (FuzzFact {index})) (Conclusions (FuzzGoal {index}))) (STV 1.0 1.0))"
                for index in range(item_count)
            ]
        )
        removed_facts = set(rng.sample(range(item_count), 5))
        removed_rules = set(rng.sample(range(item_count), 5))

        for index in sorted(removed_facts):
            self.assertEqual(handler.remove_statement(f"fuzz_fact_{index}"), 1)
        for index in sorted(removed_rules):
            self.assertEqual(handler.remove_statement(f"fuzz_rule_{index}"), 1)

        for index in range(item_count):
            with self.subTest(index=index):
                fact_exists = bool(
                    handler.query(
                        f"(: $prf (FuzzFact {index}) $tv)", timeout_sec=0
                    )
                )
                goal_exists = bool(
                    handler.query(
                        f"(: $prf (FuzzGoal {index}) $tv)", timeout_sec=0
                    )
                )
                self.assertEqual(fact_exists, index not in removed_facts)
                self.assertEqual(
                    goal_exists,
                    index not in removed_facts and index not in removed_rules,
                )

        self.assertEqual(
            len(handler._added_atoms),
            item_count * 2 - len(removed_facts) - len(removed_rules),
        )


if __name__ == "__main__":
    unittest.main()
