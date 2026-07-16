!(import! &self petta_chainer)

!(compileadd mergedSubgoalKb (: a (A) (STV 1.0 0.9)))

!(compileadd mergedSubgoalKb (: b (B) (STV 0.8 0.7)))

!(compileadd mergedSubgoalKb
   (: a_b
      (Implication (Premises (A)) (Conclusions (B)))
      (STV 0.6 0.8)))

!(compileadd mergedSubgoalKb
   (: b_d
      (Implication (Premises (B)) (Conclusions (D)))
      (STV 0.5 0.9)))

!(test
   (query 100 mergedSubgoalKb (: $prf (B) $tv))
   (: (merge/revision (rule-proof a_b a) b)
      (B)
      (STV 0.6736842105263158 0.8636363636363636)))

!(test
   (query 100 mergedSubgoalKb (: $prf (D) $tv))
   (: (rule-proof b_d (merge/revision (rule-proof a_b a) b))
      (D)
      (STV 0.40210526315789474 0.6470813397129186)))

; The merged B representative must enter b_d once. Applying b_d separately to
; both B proofs and revising the two D results counts their shared rule twice.
!(test
   (collapse
      (query 100 mergedSubgoalKb
         (: (merge/revision
               (rule-proof b_d (rule-proof a_b a))
               (rule-proof b_d b))
            (D)
            $tv)))
   ())
