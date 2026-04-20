(: xy1 (ObservedXY 10.0 100.0) (STV 1.0 1.0))
(: xy2 (ObservedXY 5.0 2.0) (STV 1.0 1.0))

(: 1 (AtTime (FeatureX 10.0) 1) (STV 1.0 0.9))
(: 2 (AtTime (FeatureY 100.0) 1) (STV 1.0 0.9))
(: 3 (AtTime (FeatureZ 20.0) 2) (STV 1.0 0.9))

(: 4 (AtTime (FeatureX 10.0) 3) (STV 1.0 0.9))
(: 5 (AtTime (FeatureY 100.0) 3) (STV 1.0 0.9))
(: 6 (AtTime (FeatureZ 21.0) 4) (STV 1.0 0.9))

(: 7 (AtTime (FeatureX 10.0) 5) (STV 1.0 0.9))
(: 8 (AtTime (FeatureY 100.0) 5) (STV 1.0 0.9))
(: 9 (AtTime (FeatureZ 19.0) 6) (STV 1.0 0.9))

(: 10 (AtTime (FeatureX 5.0) 7) (STV 1.0 0.9))
(: 11 (AtTime (FeatureY 2.0) 7) (STV 1.0 0.9))
(: 12 (AtTime (FeatureZ 7.0) 8) (STV 1.0 0.9))

(: 13 (AtTime (FeatureX 5.0) 9) (STV 1.0 0.9))
(: 14 (AtTime (FeatureY 2.0) 9) (STV 1.0 0.9))
(: 15 (AtTime (FeatureZ 8.0) 10) (STV 1.0 0.9))

(: 16 (AtTime (FeatureX 5.0) 11) (STV 1.0 0.9))
(: 17 (AtTime (FeatureY 2.0) 11) (STV 1.0 0.9))
(: 18 (AtTime (FeatureZ 7.0) 12) (STV 1.0 0.9))

(: rule (Implication (Premises (AtTime $x $t) (AtTime $y $t))
                     (Conclusions (AtTime (And $x $y) $t))) (STV 1.0 1.0))

(: sample_rule
   (Implication
      (Premises
         (AtTime (And (FeatureX $xv) (FeatureY $yv)) $t)
         (Compute + ($t 1) -> $t1)
         (AtTime (FeatureZ $zv) $t1))
      (Conclusions (NextZSample $xv $yv $zv)))
   (STV 1.0 1.0))
