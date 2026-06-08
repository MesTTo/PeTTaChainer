!(import! &self petta_chainer)

!(compileadd implicationPremiseKb
   (: ab_c
      (Implication
         (Premises
            (Implication (Premises (A)) (Conclusions (B))))
         (Conclusions
            (C)))
      (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(compileadd implicationPremiseKb
   (: a_b
      (Implication
         (Premises
            (A))
         (Conclusions
            (B)))
      (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test
   (query 60 implicationPremiseKb
      (: $prf (Implication (Premises (A)) (Conclusions (B)))
         (CTV (STV 1.0 1.0) (STV 0.5 0.0))))
   (: (rule-proof rule-proof total-implication (rule-proof a_b (ctx proof 0)) unknown)
      (Implication (Premises (A)) (Conclusions (B)))
      (CTV (STV 1.0 1.0) (STV 0.5 0.0))))

!(test
   (query 60 implicationPremiseKb (: $prf (C) $tv))
   (: (rule-proof ab_c (rule-proof rule-proof total-implication (rule-proof a_b (ctx proof 2)) unknown))
      (C)
      (STV 1.0 1.0)))

!(test
   (query 60 implicationPremiseKb
      (: $prf
         (Implication
            (Premises (Not (Dog)))
            (Conclusions (Dog)))
         $tv))
   (: (rule-proof rule-proof total-implication (ctx proof 4) unknown)
      (Implication (Premises (Not (Dog))) (Conclusions (Dog)))
      (CTV (STV 0.0 1.0) (STV 0.5 0.0))))

!(test
   (query 60 implicationPremiseKb
      (: $prf
         (Implication
            (Premises (Not (Dog)))
            (Conclusions (Not (Dog))))
         (CTV (STV 1.0 1.0) (STV 0.5 0.0))))
   (: (rule-proof rule-proof total-implication (rule-proof conjunction (negated (ctx proof 6))) unknown)
      (Implication (Premises (Not (Dog))) (Conclusions (Not (Dog))))
      (CTV (STV 1.0 1.0) (STV 0.5 0.0))))

!(compileadd multiPremiseImplicationQueryKb
   (: ab_c
      (Implication
         (Premises
            (A)
            (B))
         (Conclusions
            (C)))
      (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test
   (query 60 multiPremiseImplicationQueryKb
      (: $prf (Implication (Premises (A) (B)) (Conclusions (C))) $tv))
   (: (rule-proof rule-proof total-implication
        (rule-proof ab_c (rule-proof conjunction (ctx proof 8) (ctx proof 8 1)))
        unknown)
      (Implication (Premises (A) (B)) (Conclusions (C)))
      (CTV (STV 1.0 1.0) (STV 0.5 0.0))))

!(test
   (query 60 implicationPremiseKb
      (: $prf
         (Implication
            (Premises
               (Implication (Premises (A)) (Conclusions (B)))
               (A))
            (Conclusions (B)))
         $tv))
   (: (rule-proof rule-proof total-implication (rule-proof a_b (ctx proof 10 1)) unknown)
      (Implication
         (Premises
            (Implication (Premises (A)) (Conclusions (B)))
            (A))
         (Conclusions (B)))
      (CTV (STV 1.0 1.0) (STV 0.5 0.0))))

!(set-context-polymorphic-facts kbRelativeImplicationQueryKb true)

!(compileadd kbRelativeImplicationQueryKb (: b (B) (STV 1.0 1.0)))

!(compileadd kbRelativeImplicationQueryKb
   (: ab_c
      (Implication
         (Premises
            (A)
            (B))
         (Conclusions
            (C)))
      (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test
   (query 60 kbRelativeImplicationQueryKb
      (: $prf (Implication (Premises (A)) (Conclusions (C)))
         (CTV (STV 1.0 1.0) (STV 0.5 0.0))))
   (: (rule-proof rule-proof total-implication
        (rule-proof ab_c (rule-proof conjunction (ctx proof 12) b))
        unknown)
      (Implication (Premises (A)) (Conclusions (C)))
      (CTV (STV 1.0 1.0) (STV 0.5 0.0))))

!(test (query 10 kbRelativeImplicationQueryKb (: $prf (B) $tv))
   (: b (B) (STV 1.0 1.0)))

!(compileadd (contextualFactsKb LOCAL Nil) (: local-fact (LocalFact) (STV 1.0 1.0)))

!(test (query 10 contextualFactsKb (: $prf (LocalFact) $tv)) ())

!(test (query 10 (contextualFactsKb LOCAL Nil) (: local-fact (LocalFact) (STV 1.0 1.0)))
   (: local-fact
      (Implication (Premises (LocalFact)) (Conclusions (LocalFact)))
      (STV 1.0 1.0)))

!(compileadd biImplicationKb (: a (A) (STV 1.0 1.0)))

!(compileadd biImplicationKb
   (: a_iff_b
      (BiImplication
         (Premises (A))
         (Conclusions (B)))
      (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test (query 30 biImplicationKb (: $prf (B) $tv))
   (: (rule-proof (bi-forward a_iff_b) a) (B) (STV 1.0 1.0)))

!(compileadd biImplicationKb (: b (B2) (STV 1.0 1.0)))

!(compileadd biImplicationKb
   (: a2_iff_b2
      (BiImplication
         (Premises (A2))
         (Conclusions (B2)))
      (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test (query 30 biImplicationKb (: $prf (A2) $tv))
   (: (rule-proof (bi-backward a2_iff_b2) b) (A2) (STV 1.0 1.0)))

!(test
   (query 60 biImplicationKb
      (: $prf
         (BiImplication
            (Premises (A))
            (Conclusions (B)))
         $tv))
   (: (rule-proof rule-proof bidirectional
        (rule-proof (bi-forward a_iff_b) (ctx proof 14))
        (rule-proof (bi-backward a_iff_b) (ctx proof 15)))
      (BiImplication (Premises (A)) (Conclusions (B)))
      (STV 1.0 1.0)))
