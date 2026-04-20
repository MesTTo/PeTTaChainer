!(import! &self petta_chainer)

!(compileadd kb (: prfA (Score A 1) (STV 1.0 1.0)))
!(compileadd kb (: prfB (Score B 2) (STV 1.0 1.0)))
!(compileadd kb (: prfC (Score C 3) (STV 1.0 1.0)))

!(test
   (collapse
      (query 30 kb
         (: $prf
            (FoldAll (Score $name $n) $n 0 (|-> ($acc $elem) (+ $acc $elem)) -> $total)
            $tv)))
   ((: (rule-proof prfA cpu) (FoldAll (Score $_name $_n) $_n 0 lambda_19 -> 6) (STV 1.0 1.0))))

