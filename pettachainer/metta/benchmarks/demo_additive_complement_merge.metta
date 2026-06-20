!(import! &self petta_chainer)

!(compileadd additiveComplementShowcaseKb (: d (Dog) (STV 0.5 1.0)))

!(add-to-kb
   (rules
      ((((Dog) (additiveComplementShowcaseKb $ctx $vars) $prf $atv)
        (CPU MpFormula ((STV 0.25 0.5) $atv) $tv))
       |-
       ((Animal) (additiveComplementShowcaseKb $ctx $vars) (pos-branch $prf) $tv))))

!(add-to-kb
   (rules
      ((((Dog) (additiveComplementShowcaseKb $ctx $vars) $prf $atv)
        (CPU NotFormula ($atv) $not-atv)
        (CPU MpFormula ((STV 0.75 0.5) $not-atv) $tv))
       |-
       ((Animal) (additiveComplementShowcaseKb $ctx $vars) (neg-branch (negated $prf)) $tv))))

!(collapse (query 100 additiveComplementShowcaseKb (: $prf (Animal) $tv)))

!(evidence-sets-complementary?
   ((fact-ev (additiveComplementShowcaseKb MAIN Nil) d (Dog)))
   ((not-fact-ev (additiveComplementShowcaseKb MAIN Nil) d (Dog))))

!(additive-complement-tv (STV 0.125 0.25) (STV 0.375 0.25))
