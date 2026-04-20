!(import! &self petta_chainer)

!(compileadd kb (: xy1 (ObservedXY 10.0 100.0) (STV 1.0 1.0)))
!(compileadd kb (: xy2 (ObservedXY 5.0 2.0) (STV 1.0 1.0)))

!(compileadd kb (: fx1 (AtTime (FeatureX 10.0) 1) (STV 1.0 0.9)))
!(compileadd kb (: fy1 (AtTime (FeatureY 100.0) 1) (STV 1.0 0.9)))
!(compileadd kb (: fz2 (AtTime (FeatureZ 20.0) 2) (STV 1.0 0.9)))

!(compileadd kb (: fx3 (AtTime (FeatureX 10.0) 3) (STV 1.0 0.9)))
!(compileadd kb (: fy3 (AtTime (FeatureY 100.0) 3) (STV 1.0 0.9)))
!(compileadd kb (: fz4 (AtTime (FeatureZ 21.0) 4) (STV 1.0 0.9)))

!(compileadd kb (: fx5 (AtTime (FeatureX 10.0) 5) (STV 1.0 0.9)))
!(compileadd kb (: fy5 (AtTime (FeatureY 100.0) 5) (STV 1.0 0.9)))
!(compileadd kb (: fz6 (AtTime (FeatureZ 19.0) 6) (STV 1.0 0.9)))

!(compileadd kb (: fx7 (AtTime (FeatureX 5.0) 7) (STV 1.0 0.9)))
!(compileadd kb (: fy7 (AtTime (FeatureY 2.0) 7) (STV 1.0 0.9)))
!(compileadd kb (: fz8 (AtTime (FeatureZ 7.0) 8) (STV 1.0 0.9)))

!(compileadd kb (: fx9 (AtTime (FeatureX 5.0) 9) (STV 1.0 0.9)))
!(compileadd kb (: fy9 (AtTime (FeatureY 2.0) 9) (STV 1.0 0.9)))
!(compileadd kb (: fz10 (AtTime (FeatureZ 8.0) 10) (STV 1.0 0.9)))

!(compileadd kb (: fx11 (AtTime (FeatureX 5.0) 11) (STV 1.0 0.9)))
!(compileadd kb (: fy11 (AtTime (FeatureY 2.0) 11) (STV 1.0 0.9)))
!(compileadd kb (: fz12 (AtTime (FeatureZ 7.0) 12) (STV 1.0 0.9)))

!(compileadd kb
   (: conjunctionRule
      (Implication (Premises (AtTime $x $t) (AtTime $y $t))
         (Conclusions (AtTime (And $x $y) $t)))
      (STV 1.0 1.0)))

!(compileadd kb
   (: sampleRule
      (Implication
         (Premises
            (AtTime (And (FeatureX $xv) (FeatureY $yv)) $t)
            (Compute + ($t 1) -> $t1)
            (AtTime (FeatureZ $zv) $t1))
         (Conclusions (NextZSample $xv $yv $zv)))
      (STV 1.0 1.0)))

!(test
   (fold-flat
      (|-> ($acc $_item) (+ $acc 1))
      0
      (collapse (query 100 kb (: $prf (NextZSample 10.0 100.0 $zv) $tv))))
   3)

!(test
   (fold-flat
      (|-> ($acc $_item) (+ $acc 1))
      0
      (collapse (query 100 kb (: $prf (NextZSample 5.0 2.0 $zv) $tv))))
   3)

!(test
   (let*
      (($zcounts
           (DistValueCountAcc
              (DistValueCountAcc
                 (DistValueCountAcc (PairCounts ()) 20.0)
                 21.0)
              19.0))
       ($dist (PairCountsToDist $zcounts)))
      (let (STV $s $c) (DistGreaterThanFormula $dist 19.5)
         (and (> $s 0.66) (< $s 0.67))))
   true)

!(test
   (let*
      (($zcounts
           (DistValueCountAcc
              (DistValueCountAcc
                 (DistValueCountAcc (PairCounts ()) 7.0)
                 8.0)
              7.0))
       ($dist (PairCountsToDist $zcounts)))
      (let (STV $s $c) (DistGreaterThanFormula $dist 7.5)
         (and (> $s 0.33) (< $s 0.34))))
   true)
