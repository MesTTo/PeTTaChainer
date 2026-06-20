!(import! &self petta_chainer)

!(test
   (evidence-negate (fact-ev (kb MAIN Nil) d (Dog)))
   (not-fact-ev (kb MAIN Nil) d (Dog)))

!(test
   (evidence-sets-overlap?
      ((fact-ev (kb MAIN Nil) d (Dog)))
      ((not-fact-ev (kb MAIN Nil) d (Dog))))
   false)

!(test
   (evidence-sets-complementary?
      ((fact-ev (kb MAIN Nil) d (Dog)))
      ((not-fact-ev (kb MAIN Nil) d (Dog))))
   true)

!(test
   (additive-complement-tv (STV 0.125 0.25) (STV 0.375 0.25))
   (STV 0.5 0.5))

!(test
   (merge-proof-atoms
      ((Animal) (kb MAIN Nil) (rule-proof d_a (fact-ev (kb MAIN Nil) d (Dog))) (STV 0.125 0.25))
      ((Animal) (kb MAIN Nil) (rule-proof nd_a (not-fact-ev (kb MAIN Nil) d (Dog))) (STV 0.375 0.25)))
   ((Animal) (kb MAIN Nil)
      (merge/additive-complement
         (rule-proof d_a (fact-ev (kb MAIN Nil) d (Dog)))
         (rule-proof nd_a (not-fact-ev (kb MAIN Nil) d (Dog))))
      (STV 0.5 0.5)))

!(compileadd negEvidenceMergeKb
   (: nd_a (Implication (Premises (Not (Dog))) (Conclusions (Animal))) (STV 0.75 0.5)))

!(compileadd negEvidenceMergeKb
   (: d_a (Implication (Premises (Dog)) (Conclusions (Animal))) (STV 0.25 0.5)))

!(compileadd negEvidenceMergeKb (: d (Dog) (STV 0.5 1.0)))

!(test (collapse (query 100 negEvidenceMergeKb (: $prf (Animal) $tv)))
   ((: (rule-proof d_a d) (Animal) (STV 0.5 0.5))))

!(test (length (collapse (query 100 negEvidenceMergeKb (: $prf (Animal) $tv)))) 1)

!(compileadd totalMpFallbackKb (: d (Dog) (STV 0.5 1.0)))

!(compileadd totalMpFallbackKb
   (: d_a (Implication (Premises (Dog)) (Conclusions (Animal))) (STV 0.8 0.6)))

!(test (collapse (query 100 totalMpFallbackKb (: $prf (Animal) $tv)))
   ((: (rule-proof d_a d) (Animal) (STV 0.5 0.4))))

!(compileadd totalMpNegOnlyKb (: d (Dog) (STV 0.5 1.0)))

!(compileadd totalMpNegOnlyKb
   (: nd_a (Implication (Premises (Not (Dog))) (Conclusions (Animal))) (STV 0.8 0.6)))

!(test (collapse (query 100 totalMpNegOnlyKb (: $prf (Animal) $tv)))
   ((: (rule-proof nd_a (negated d)) (Animal) (STV 0.5 0.4))))

!(compileadd additiveMergeRuntimeKb (: d (Dog) (STV 0.5 1.0)))

!(add-to-kb
   (rules
      ((((Dog) (additiveMergeRuntimeKb $ctx $vars) $prf $atv)
        (CPU MpFormula ((STV 0.25 0.5) $atv) $tv))
       |-
       ((Animal) (additiveMergeRuntimeKb $ctx $vars) (pos-branch $prf) $tv))))

!(add-to-kb
   (rules
      ((((Dog) (additiveMergeRuntimeKb $ctx $vars) $prf $atv)
        (CPU NotFormula ($atv) $not-atv)
        (CPU MpFormula ((STV 0.75 0.5) $not-atv) $tv))
       |-
       ((Animal) (additiveMergeRuntimeKb $ctx $vars) (neg-branch (negated $prf)) $tv))))

!(test
   (collapse (query 100 additiveMergeRuntimeKb (: $prf (Animal) $tv)))
   ((: (merge/additive-complement
          (rule-proof neg-branch (negated d))
          (rule-proof pos-branch d))
       (Animal)
       (STV 0.5 0.5))))

!(test
   (length
      (collapse
         (query 100 additiveMergeRuntimeKb
            (: $prf (Animal) $tv))))
   1)
