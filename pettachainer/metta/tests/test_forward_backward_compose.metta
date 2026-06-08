!(import! &self petta_chainer)

!(compileadd bwdOnlyKb (: a0 (A) (STV 1.0 1.0)))

!(compileadd bwdOnlyKb (: r1 (Implication (Premises (A)) (Conclusions (B))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(compileadd bwdOnlyKb (: r2 (Implication (Premises (B)) (Conclusions (Goal))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test (query 2 bwdOnlyKb (: $p (Goal) $tv)) ())

!(test (query 4 bwdOnlyKb (: $p (Goal) $tv))
   (: (rule-proof r2 (rule-proof r1 a0)) (Goal) (STV 1.0 1.0)))

!(test
   (query 100 bwdOnlyKb
      (: $p (Implication (Premises (A)) (Conclusions (Goal)))
         (CTV (STV 1.0 1.0) (STV 0.5 0.0))))
   (: (rule-proof rule-proof total-implication (rule-proof r2 (rule-proof r1 (ctx proof 0))) unknown)
      (Implication (Premises (A)) (Conclusions (Goal)))
      (CTV (STV 1.0 1.0) (STV 0.5 0.0))))

!(compileadd transitiveClosedKb
   (: ax-tr
      (Implication
         (Premises (Provable (→ $psi $chi)) (Provable (→ $phi $psi)))
         (Conclusions (Provable (→ $phi $chi))))
      (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(compileadd transitiveClosedKb (: given-imp1 (Provable (→ (PropP) (PropQ))) (STV 1.0 1.0)))

!(compileadd transitiveClosedKb (: given-imp2 (Provable (→ (PropQ) (PropT))) (STV 1.0 1.0)))

!(test
   (query 20 transitiveClosedKb (: $p (Provable (→ (PropP) (PropT))) $tv))
   (: (rule-proof ax-tr (rule-proof conjunction given-imp2 given-imp1))
      (Provable (→ (PropP) (PropT)))
      (STV 1.0 1.0)))

!(compileadd openImplicationKb (: r1 (Implication (Premises (A)) (Conclusions (B))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test
   (query 100 openImplicationKb
      (: $p (Implication (Premises (A)) (Conclusions (B))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))
   (: (rule-proof rule-proof total-implication (rule-proof r1 (ctx proof 2)) (rule-proof r1 (ctx proof 3)))
      (Implication (Premises (A)) (Conclusions (B)))
      (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(compileadd openHashImplicationKb (: r2 (Implication (Premises (A)) (Conclusions (C))) (CTV (STV 1.0 0.5) (STV 0.0 1.0))))

!(compileadd openHashImplicationKb (: r3 (Implication (Premises (C)) (Conclusions (B))) (CTV (STV 1.0 0.5) (STV 0.0 1.0))))

!(test
   (query 100 openHashImplicationKb
      (: $p (Implication (Premises (#)) (Conclusions (B))) (CTV (STV 1.0 1.0) (STV 0.5 0.0))))
   (: (rule-proof rule-proof total-implication (ctx proof 4) unknown)
      (Implication (Premises (#)) (Conclusions (B)))
      (CTV (STV 1.0 1.0) (STV 0.5 0.0))))

!(compileadd openHashPatternImplicationKb
   (: featureRule (Implication (Premises (Feature a)) (Conclusions (Target))) (CTV (STV 1.0 0.5) (STV 0.0 1.0))))

!(test
   (query 100 openHashPatternImplicationKb
      (: $p (Implication (Premises (Feature #)) (Conclusions (Target))) (CTV (STV 1.0 0.5) (STV 0.0 1.0))))
   (: (rule-proof rule-proof total-implication (rule-proof featureRule (ctx proof 6)) (rule-proof featureRule (ctx proof 7)))
      (Implication (Premises (Feature #)) (Conclusions (Target)))
      (CTV (STV 1.0 0.5) (STV 0.0 1.0))))

!(compileadd openVariableConclusionImplicationKb (: tallAlice (Tall alice) (STV 0.9 0.5)))

!(compileadd openVariableConclusionImplicationKb (: femaleAlice (Female alice) (STV 0.9 0.5)))

!(compileadd openVariableConclusionImplicationKb (: tallMary (Tall mary) (STV 0.9 0.5)))

!(compileadd openVariableConclusionImplicationKb (: femaleMary (Female mary) (STV 0.9 0.5)))

!(compileadd openVariableConclusionImplicationKb
   (: copyPredicate
      (Implication
         (Premises (And ($p1 $x) ($p2 $x)) ($p1 $y))
         (Conclusions ($p2 $y)))
      (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test
   (query 100 openVariableConclusionImplicationKb
      (: $p
         (Implication (Premises (Tall $x)) (Conclusions (Female $x)))
         (CTV (STV 0.9639 0.5) (STV 0.5 0.0))))
   (: (rule-proof rule-proof total-implication
        (rule-proof copyPredicate
           (rule-proof conjunction
              (ctx proof 8)
              (rule-proof disjunction
                 (rule-proof conjunction tallAlice femaleAlice)
                 (rule-proof conjunction tallMary femaleMary))))
        unknown)
      (Implication (Premises (Tall $_x)) (Conclusions (Female $_x)))
      (CTV (STV 0.9639 0.5) (STV 0.5 0.0))))

!(test
   (query 100 openVariableConclusionImplicationKb
      (: $p (Implication (Premises (Tall $x)) (Conclusions (Female $x))) $tv))
   (: (rule-proof rule-proof total-implication
        (rule-proof copyPredicate
           (rule-proof conjunction
              (ctx proof 10)
              (rule-proof disjunction
                 (rule-proof conjunction tallAlice femaleAlice)
                 (rule-proof conjunction tallMary femaleMary))))
        unknown)
      (Implication (Premises (Tall $_x)) (Conclusions (Female $_x)))
      (CTV (STV 0.9639 0.5) (STV 0.5 0.0))))

!(test
   (query 100 openVariableConclusionImplicationKb
      (: $proof
         (Implication (Premises ($p $x)) (Conclusions ($p $x)))
         (CTV (STV 1.0 1.0) (STV 0.0 1.0))))
   (: (rule-proof rule-proof total-implication (ctx proof 12) (ctx proof 13))
      (Implication (Premises ($_p $_x)) (Conclusions ($_p $_x)))
      (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test
   (query 100 openVariableConclusionImplicationKb
      (: $proof
         (Implication (Premises (Female $x)) (Conclusions (Tall $x)))
         (CTV (STV 0.9639 0.5) (STV 0.5 0.0))))
   (: (rule-proof rule-proof total-implication
        (rule-proof copyPredicate
           (rule-proof conjunction
              (ctx proof 14)
              (rule-proof disjunction
                 (rule-proof conjunction femaleAlice tallAlice)
                 (rule-proof conjunction femaleMary tallMary))))
        unknown)
      (Implication (Premises (Female $_x)) (Conclusions (Tall $_x)))
      (CTV (STV 0.9639 0.5) (STV 0.5 0.0))))

!(compileadd existentialDisjunctionKb (: pa (P a) (STV 0.8 0.5)))

!(compileadd existentialDisjunctionKb (: pb (P b) (STV 0.6 0.7)))

!(compileadd existentialDisjunctionKb
   (: pToT (Implication (Premises (P $x)) (Conclusions (T))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test
   (query 100 existentialDisjunctionKb (: $prf (T) $tv))
   (: (rule-proof pToT (rule-proof disjunction pa pb)) (T) (STV 0.9199999999999999 0.5)))

!(compileadd composeKb (: a0 (A) (STV 1.0 1.0)))

!(compileadd composeKb (: r1 (Implication (Premises (A)) (Conclusions (B))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(compileadd composeKb (: r2 (Implication (Premises (B)) (Conclusions (Goal))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test (let $_ (forward-chain 1 composeKb) (query 2 composeKb (: $p (Goal) $tv)))
   (: (rule-proof r2 (r1 a0)) (Goal) (STV 1.0 1.0)))

!(compileadd composeKbShort (: a0 (A) (STV 1.0 1.0)))

!(compileadd composeKbShort (: r1 (Implication (Premises (A)) (Conclusions (B))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(compileadd composeKbShort (: r2 (Implication (Premises (B)) (Conclusions (Goal))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test
   (let $_ (forward-chain 1 composeKbShort)
      (query 1 composeKbShort (: $p (Goal) $tv)))
   ())

!(compileadd noReuseKb (: x (X) (STV 1.0 1.0)))

!(compileadd noReuseKb (: ra (Implication (Premises (X)) (Conclusions (A))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(compileadd noReuseKb (: rb (Implication (Premises (X)) (Conclusions (B))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(compileadd noReuseKb (: rc (Implication (Premises (A) (B)) (Conclusions (C))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test (query 100 noReuseKb (: $p (C) $tv)) ())

!(compileadd independentKb (: x (X) (STV 1.0 1.0)))

!(compileadd independentKb (: b (B) (STV 1.0 1.0)))

!(compileadd independentKb (: ra (Implication (Premises (X)) (Conclusions (A))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(compileadd independentKb (: rc (Implication (Premises (A) (B)) (Conclusions (C))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(test (query 100 independentKb (: $p (C) $tv))
   (: (rule-proof rc (rule-proof conjunction (rule-proof ra x) b)) (C) (STV 1.0 1.0)))

!(compileadd derivedAndRuleKb (: yearsRule (Implication (Premises (YearsExp $p 10)) (Conclusions (IndustryVeteran $p))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(compileadd derivedAndRuleKb (: expertRule (Implication (Premises (And (IndustryVeteran $p) (ManagedTeam $p))) (Conclusions (Expert $p))) (CTV (STV 1.0 0.95) (STV 0.0 1.0))))

!(compileadd derivedAndRuleKb (: seniorRule (Implication (Premises (And (Expert $p) (CertifiedEthical $p))) (Conclusions (SeniorExpert $p))) (CTV (STV 1.0 1.0) (STV 0.0 1.0))))

!(compileadd derivedAndRuleKb (: yearsFact (YearsExp kebede 10) (STV 1.0 1.0)))

!(compileadd derivedAndRuleKb (: mgmtFact (ManagedTeam kebede) (STV 1.0 1.0)))

!(compileadd derivedAndRuleKb (: ethicsFact (CertifiedEthical kebede) (STV 1.0 1.0)))

!(test
   (query 50 derivedAndRuleKb (: $p (Expert kebede) $tv))
   (: (rule-proof expertRule (conjunction (rule-proof yearsRule yearsFact) mgmtFact))
      (Expert kebede)
      (STV 1.0 0.95)))

!(test
   (query 50 derivedAndRuleKb (: $p (SeniorExpert kebede) $tv))
   (: (rule-proof seniorRule
        (conjunction
           (rule-proof expertRule (conjunction (rule-proof yearsRule yearsFact) mgmtFact))
           ethicsFact))
      (SeniorExpert kebede)
      (STV 1.0 0.95)))
