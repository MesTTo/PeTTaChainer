!(import! &self chainer/proof_structure_audit)

; The real isolate-proof result captured from impressive_incident_response.py
; (a 3-way merge/revision with mixed bare / rule-proof head forms). The expected
; verdict below is the exact content of the demo's proof-structure.json.
(= (DemoIsolateResult)
   (: (merge/revision (merge/revision (isolate_policy (pii_incident (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction phish_laptop trust_primary_1)) trust_primary_2)) trust_primary_3)) trust_primary_4)) trust_primary_5)) trust_primary_6)) customerdb_pii))) (rule-proof isolate_policy (pii_incident (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction phish_laptop trust_primary_1)) trust_primary_2)) trust_primary_3)) trust_primary_4)) trust_primary_5)) trust_primary_6)) customerdb_pii)))) (rule-proof isolate_policy (rule-proof pii_incident (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction (lateral_move (rule-proof conjunction phish_laptop trust_primary_1)) trust_primary_2)) trust_primary_3)) trust_primary_4)) trust_primary_5)) trust_primary_6)) customerdb_pii)))) (Action Isolate CustomerDB) (STV 0.7899039623947294 0.5341907572135067)))

(= (DemoProofTerm (: $prf $_stmt $_tv)) $prf)

; Granular counts (proof-structure.json operator_counts), for easy diagnosis.
!(test (count-token lateral_move (DemoProofTerm (DemoIsolateResult))) 18)
!(test (count-token (rule-proof) (DemoProofTerm (DemoIsolateResult))) 0)
!(test (count-token rule-proof (DemoProofTerm (DemoIsolateResult))) 24)
!(test (count-token isolate_policy (DemoProofTerm (DemoIsolateResult))) 3)
!(test (count-token pii_incident (DemoProofTerm (DemoIsolateResult))) 3)
!(test (count-token merge/revision (DemoProofTerm (DemoIsolateResult))) 2)

; Forbidden labels are absent.
!(test (count-any (noise_1 noise_2 trust_secondary_1 trust_secondary_2 rotate_policy token_seed)
                  (DemoProofTerm (DemoIsolateResult))) 0)

; Structural booleans.
!(test (has-primary-chain? (DemoProofTerm (DemoIsolateResult)) 6) True)
!(test (has-pii-gate? (DemoProofTerm (DemoIsolateResult)) 6) True)
!(test (has-isolate-policy-step? (DemoProofTerm (DemoIsolateResult))) True)

; Full verdict matches proof-structure.json field for field.
!(test
   (proof-structure-verdict (DemoIsolateResult) 6 (noise_1 trust_secondary_1 rotate_policy token_seed))
   (ProofAudit
      (target-action-matches True)
      (truth-value (STV 0.7899039623947294 0.5341907572135067))
      (primary-chain-found True)
      (pii-gate-found True)
      (isolate-policy-step-found True)
      (forbidden-count 0)
      (op-lateral_move 18)
      (op-pii_incident 3)
      (op-isolate_policy 3)
      (op-rule-proof 24)
      (op-merge/revision 2)))
