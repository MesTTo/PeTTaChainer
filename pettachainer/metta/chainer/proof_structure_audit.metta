; Structural audit of an isolate-proof result atom, by native MeTTa matching.
;
; Replaces the Python s-expression parser (parse_sexpr / walk_sexpr) in
; impressive_incident_response.py. The proof term the chainer materializes uses:
;   - bare rule heads: (lateral_move <body>), and isolate_policy / pii_incident
;     appear both bare and (rule-proof <label> <body>),
;   - (rule-proof conjunction <left> <leaf>) for two-premise conjunctions,
;   - (merge/revision <left> <right>) when a goal has several proofs,
;   - bare leaf labels (phish_laptop, customerdb_pii, trust_primary_N).
; No imports: it uses only builtins (car-atom, cdr-atom, is-expr, if, case).

; -- count a symbol anywhere in a proof tree --
(= (count-token $sym $term)
   (if (== $term $sym)
      1
      (if (is-expr $term) (count-token-children $sym $term) 0)))
(= (count-token-children $sym $expr)
   (if (== $expr ())
      0
      (+ (count-token $sym (car-atom $expr))
         (count-token-children $sym (cdr-atom $expr)))))

; -- sum counts over a list of symbols (for label groups passed from Python) --
(= (count-any $list $term)
   (if (== $list ())
      0
      (+ (count-token (car-atom $list) $term)
         (count-any (cdr-atom $list) $term))))

; -- primary chain: nested (lateral_move (rule-proof conjunction <prev> trust_primary_N)),
;    bottoming at phish_laptop. Returns the hop count, or -1 if not a clean chain. --
(= (primary-chain-depth $term)
   (case $term (
      ((lateral_move (rule-proof conjunction phish_laptop $_leaf)) 1)
      ((lateral_move (rule-proof conjunction $inner $_leaf))
         (let $d (primary-chain-depth $inner) (if (< $d 0) -1 (+ $d 1))))
      ($_other -1))))

(= (has-primary-chain? $term $expected)
   (if (== (primary-chain-depth $term) $expected)
      True
      (if (is-expr $term) (has-primary-chain-children? $term $expected) False)))
(= (has-primary-chain-children? $expr $expected)
   (if (== $expr ())
      False
      (if (has-primary-chain? (car-atom $expr) $expected)
         True
         (has-primary-chain-children? (cdr-atom $expr) $expected))))

; -- pii gate: (pii_incident (rule-proof conjunction <chain> customerdb_pii)),
;    bare or rule-proof-wrapped, gating the full primary chain. --
(= (pii-gate-here? $term $expected)
   (case $term (
      ((pii_incident (rule-proof conjunction $chain customerdb_pii))
         (== (primary-chain-depth $chain) $expected))
      ((rule-proof pii_incident (rule-proof conjunction $chain customerdb_pii))
         (== (primary-chain-depth $chain) $expected))
      ($_other False))))
(= (has-pii-gate? $term $expected)
   (if (pii-gate-here? $term $expected)
      True
      (if (is-expr $term) (has-pii-gate-children? $term $expected) False)))
(= (has-pii-gate-children? $expr $expected)
   (if (== $expr ())
      False
      (if (has-pii-gate? (car-atom $expr) $expected)
         True
         (has-pii-gate-children? (cdr-atom $expr) $expected))))

; -- isolate policy step: (isolate_policy <body>) / (rule-proof isolate_policy <body>)
;    whose body contains a pii_incident. --
(= (isolate-step-here? $term)
   (case $term (
      ((isolate_policy $body) (> (count-token pii_incident $body) 0))
      ((rule-proof isolate_policy $body) (> (count-token pii_incident $body) 0))
      ($_other False))))
(= (has-isolate-policy-step? $term)
   (if (isolate-step-here? $term)
      True
      (if (is-expr $term) (has-isolate-step-children? $term) False)))
(= (has-isolate-step-children? $expr)
   (if (== $expr ())
      False
      (if (has-isolate-policy-step? (car-atom $expr))
         True
         (has-isolate-step-children? (cdr-atom $expr)))))

; -- top-level verdict over a result atom (: <proof> (Action Isolate CustomerDB) (STV s c)).
;    $forbidden is a list of forbidden labels/prefix-members to count (passed from Python). --
(= (proof-structure-verdict $result $expected $forbidden)
   (case $result (
      ((: $prf (Action Isolate CustomerDB) (STV $s $c))
         (ProofAudit
            (target-action-matches True)
            (truth-value (STV $s $c))
            (primary-chain-found (has-primary-chain? $prf $expected))
            (pii-gate-found (has-pii-gate? $prf $expected))
            (isolate-policy-step-found (has-isolate-policy-step? $prf))
            (forbidden-count (count-any $forbidden $prf))
            (op-lateral_move (count-token lateral_move $prf))
            (op-pii_incident (count-token pii_incident $prf))
            (op-isolate_policy (count-token isolate_policy $prf))
            (op-rule-proof (count-token rule-proof $prf))
            (op-merge/revision (count-token merge/revision $prf))))
      ($_other (ProofAudit (target-action-matches False))))))
