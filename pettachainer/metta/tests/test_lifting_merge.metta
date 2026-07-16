!(import! &self petta_chainer)

(= (lifting-merge-proof? $proof)
   (if (is-expr $proof) (== (car-atom $proof) merge/lifting) false))

; Two independent rules applied to one fact share only that fact. Factoring the
; fact out lets the rule evidence revise before the fact is applied once.
!(compileadd sameRuleTvKb (: a (A i) (STV 1.0 1.0)))

!(compileadd sameRuleTvKb
   (: ab1
      (Implication (Premises (A $x)) (Conclusions (B $x)))
      (STV 0.6 0.9)))

!(compileadd sameRuleTvKb
   (: ab2
      (Implication (Premises (A $x)) (Conclusions (B $x)))
      (STV 0.6 0.9)))

!(test
   (let
      (: $proof (B i) $tv)
      (query 80 sameRuleTvKb (: $proof (B i) $tv))
      ((lifting-merge-proof? $proof) $tv))
   (true (STV 0.6 0.9473684210526316)))

!(test
   (let $_query-result
      (query 80 sameRuleTvKb (: $proof (B i) $tv))
      (collapse
         (once
            (match &proof
               ($_pid (merged-proof-group $_gid) $output
                  (merged $output) $_score $evidence $children)
               ((list-count $children)
                (list-count $evidence)
                (==
                   (list_to_set (proof-ref-ids $output))
                   (list_to_set $children)))))))
   ((2 3 true)))

; Unequal rule confidence used to let storage dominance discard ab2 before the
; merge. Both proofs must survive because their non-fact evidence is disjoint.
!(compileadd unequalRuleTvKb (: a (A i) (STV 1.0 1.0)))

!(compileadd unequalRuleTvKb
   (: ab1
      (Implication (Premises (A $x)) (Conclusions (B $x)))
      (STV 0.7 0.8)))

!(compileadd unequalRuleTvKb
   (: ab2
      (Implication (Premises (A $x)) (Conclusions (B $x)))
      (STV 0.6 0.9)))

!(test
   (let
      (: $proof (B i) $tv)
      (query 80 unequalRuleTvKb (: $proof (B i) $tv))
      ((lifting-merge-proof? $proof) $tv))
   (true (STV 0.6307692307692307 0.9285714285714286)))

; Lifting is n-ary. Three independent rules retain all three proof references
; and combine their residual evidence once.
!(compileadd threeRuleKb (: a (A i) (STV 1.0 1.0)))

!(compileadd threeRuleKb
   (: ab1
      (Implication (Premises (A $x)) (Conclusions (B $x)))
      (STV 0.6 0.9)))

!(compileadd threeRuleKb
   (: ab2
      (Implication (Premises (A $x)) (Conclusions (B $x)))
      (STV 0.6 0.9)))

!(compileadd threeRuleKb
   (: ab3
      (Implication (Premises (A $x)) (Conclusions (B $x)))
      (STV 0.6 0.9)))

!(test
   (let
      (: $proof (B i) $tv)
      (query 100 threeRuleKb (: $proof (B i) $tv))
      ((lifting-merge-proof? $proof) (list-count (cdr-atom $proof)) $tv))
   (true 3 (STV 0.6 0.9642857142857143)))

; A partial antecedent exercises both branches of TotalMpFormula. The revised
; positive rules and the revised default complements are each applied once.
!(compileadd partialAntecedentKb (: a (A i) (STV 0.8 0.7)))

!(compileadd partialAntecedentKb
   (: ab1
      (Implication (Premises (A $x)) (Conclusions (B $x)))
      (STV 0.7 0.8)))

!(compileadd partialAntecedentKb
   (: ab2
      (Implication (Premises (A $x)) (Conclusions (B $x)))
      (STV 0.6 0.9)))

!(test
   (let
      (: $proof (B i) $tv)
      (query 80 partialAntecedentKb (: $proof (B i) $tv))
      ((lifting-merge-proof? $proof) $tv))
   (true (STV 0.5446153846153846 0.6266666666666666)))

; Residual evidence may include separate facts as long as the shared fact is
; the only overlap between the two proof paths.
!(compileadd oneSharedFactKb (: a (A i) (STV 1.0 1.0)))
!(compileadd oneSharedFactKb (: x (X i) (STV 1.0 1.0)))
!(compileadd oneSharedFactKb (: y (Y i) (STV 1.0 1.0)))

!(compileadd oneSharedFactKb
   (: axb
      (Implication
         (Premises (And (A $z) (X $z)))
         (Conclusions (B $z)))
      (STV 0.6 0.9)))

!(compileadd oneSharedFactKb
   (: ayb
      (Implication
         (Premises (And (A $z) (Y $z)))
         (Conclusions (B $z)))
      (STV 0.6 0.9)))

!(test
   (let
      (: $proof (B i) $tv)
      (query 120 oneSharedFactKb (: $proof (B i) $tv))
      ((lifting-merge-proof? $proof) $tv))
   (true (STV 0.6 0.9473684210526316)))

; Several common facts are factored as one conjunction. The rules remain the
; independent residual evidence.
!(compileadd multiSharedFactKb (: a (A i) (STV 1.0 1.0)))
!(compileadd multiSharedFactKb (: x (X i) (STV 1.0 1.0)))

!(compileadd multiSharedFactKb
   (: axb1
      (Implication
         (Premises (And (A $z) (X $z)))
         (Conclusions (B $z)))
      (STV 0.6 0.9)))

!(compileadd multiSharedFactKb
   (: axb2
      (Implication
         (Premises (And (A $z) (X $z)))
         (Conclusions (B $z)))
      (STV 0.6 0.9)))

!(test
   (let
      (: $proof (B i) $tv)
      (query 120 multiSharedFactKb (: $proof (B i) $tv))
      ((lifting-merge-proof? $proof) $tv))
   (true (STV 0.6 0.9473684210526316)))

; A schema contributes no independent support. Two schema applications over
; the same fact therefore fall back to dominance instead of gaining confidence.
!(mark-logic-rule logicAb1)
!(mark-logic-rule logicAb2)

!(compileadd logicOnlyKb (: a (A i) (STV 1.0 1.0)))

!(compileadd logicOnlyKb
   (: logicAb1
      (Implication (Premises (A $x)) (Conclusions (B $x)))
      (STV 0.6 0.9)))

!(compileadd logicOnlyKb
   (: logicAb2
      (Implication (Premises (A $x)) (Conclusions (B $x)))
      (STV 0.6 0.9)))

!(test
   (let
      (: $proof (B i) $tv)
      (query 80 logicOnlyKb (: $proof (B i) $tv))
      ((lifting-merge-proof? $proof) $tv))
   (false (STV 0.6 0.9)))

; LikelierThan is piecewise rather than affine in each input across its kink.
; The CPU-shape guard must reject these paths and retain the dominant proof.
!(compileadd nonlinearKb (: a (A i) (STV 0.9 0.8)))
!(compileadd nonlinearKb (: x (X i) (STV 0.4 0.7)))
!(compileadd nonlinearKb (: y (Y i) (STV 0.2 0.6)))

!(compileadd nonlinearKb
   (: axb
      (Implication
         (Premises (LikelierThan (A $z) (X $z)))
         (Conclusions (B $z)))
      (STV 1.0 1.0)))

!(compileadd nonlinearKb
   (: ayb
      (Implication
         (Premises (LikelierThan (A $z) (Y $z)))
         (Conclusions (B $z)))
      (STV 1.0 1.0)))

!(test
   (let
      (: $proof (B i) $tv)
      (query 120 nonlinearKb (: $proof (B i) $tv))
      ((lifting-merge-proof? $proof) $tv))
   (false (STV 0.76 0.48)))

(= (lifting-total-mp-roundtrip?
      (roundtrip-case $antecedent $positive $negative))
   (lifting-tv-close?
      (TotalMpFormula $antecedent $positive $negative)
      (lifting-apply-residual
         $antecedent
         (total-mp-residual
            (TotalMpFormula (STV 1.0 1.0) $positive $negative)
            (TotalMpFormula (STV 0.0 1.0) $positive $negative)))))

; Boundary matrix for the affine extraction used by lifting. It includes zero
; evidence, exact endpoints, unequal branch confidence, and near-certain TVs.
!(test
   (map-flat lifting-total-mp-roundtrip?
      ((roundtrip-case (STV 0.0 0.0) (STV 0.0 0.0) (STV 0.0 0.0))
       (roundtrip-case (STV 0.0 1.0) (STV 1.0 1.0) (STV 0.2 0.2))
       (roundtrip-case (STV 1.0 1.0) (STV 1.0 1.0) (STV 0.2 0.2))
       (roundtrip-case (STV 0.5 0.5) (STV 0.8 0.9) (STV 0.1 0.2))
       (roundtrip-case (STV 0.2 0.9) (STV 0.3 0.4) (STV 0.7 0.8))
       (roundtrip-case (STV 0.8 0.1) (STV 0.9 0.7) (STV 0.4 0.6))
       (roundtrip-case (STV 0.9999 0.9999) (STV 0.9999 0.9999) (STV 0.0001 0.0001))
       (roundtrip-case (STV 0.0001 0.9999) (STV 0.0001 0.0001) (STV 0.9999 0.9999))))
   (true true true true true true true true))
