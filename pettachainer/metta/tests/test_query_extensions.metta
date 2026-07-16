!(import! &self petta_chainer)

!(compileadd variableHeadKb
   (: symmetricRule
      (Implication
         (Premises (Symmetric $relation) ($relation $left $right))
         (Conclusions ($relation $right $left)))
      (STV 0.9 0.9)))
!(compileadd variableHeadKb (: symmetricFriend (Symmetric Friend) (STV 0.9 0.9)))
!(compileadd variableHeadKb (: friendFact (Friend bob alice) (STV 0.9 0.9)))

!(test
   (query 100 variableHeadKb
      (: $proof (Friend alice $who) $tv))
   (: (rule-proof symmetricRule (rule-proof conjunction symmetricFriend friendFact))
      (Friend alice bob)
      (STV 0.7670000000000001 0.7670000000000001)))

!(compileadd naryConjunctionKb (: aFact A (STV 1.0 1.0)))
!(compileadd naryConjunctionKb (: bFact B (STV 1.0 1.0)))
!(compileadd naryConjunctionKb (: cFact C (STV 1.0 1.0)))
!(compileadd naryConjunctionKb (: dFact D (STV 1.0 1.0)))

!(test
   (query 50 naryConjunctionKb
      (: $proof (And A B C) $tv))
   (: (rule-proof conjunction aFact bFact cFact)
      (And A B C)
      (STV 1.0 1.0)))

!(test
   (query 80 naryConjunctionKb
      (: $proof (And A B C D) $tv))
   (: (rule-proof conjunction aFact bFact cFact dFact)
      (And A B C D)
      (STV 1.0 1.0)))
