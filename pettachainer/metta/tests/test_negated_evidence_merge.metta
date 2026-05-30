!(import! &self petta_chainer)

!(test
   (evidence-negate (fact-ev (kb MAIN Nil) d (Dog)))
   (not-fact-ev (kb MAIN Nil) d (Dog)))

!(test
   (evidence-sets-overlap?
      ((fact-ev (kb MAIN Nil) d (Dog)))
      ((not-fact-ev (kb MAIN Nil) d (Dog))))
   false)

!(compileadd negEvidenceMergeKb
   (: nd_a (Implication (Premises (Not (Dog))) (Conclusions (Animal))) (STV 0.75 0.5)))

!(compileadd negEvidenceMergeKb
   (: d_a (Implication (Premises (Dog)) (Conclusions (Animal))) (STV 0.25 0.5)))

!(compileadd negEvidenceMergeKb (: d (Dog) (STV 0.5 1.0)))

!(test (collapse (query 100 negEvidenceMergeKb (: $prf (Animal) $tv)))
   ((: (merge/revision (rule-proof d_a d) (rule-proof nd_a (negated d)))
       (Animal)
       (STV 0.25 0.39999999999999997))))
