!(import! &self petta_chainer)

!(import! &data data_test)

!(compileadd kb (get-atoms &data))

!(let*
   (($samples (collapse (query 100 kb (: $prf (NextZSample 10.0 100.0 $zv) $tv))))
    ($zcounts
       (fold-flat
          (|-> ($acc $item)
             (let (: $_prf (NextZSample 10.0 100.0 $value) $_tv) $item
                (DistValueCountAcc $acc $value)))
          (PairCounts ())
          $samples)))
   (ParticlePairs (PairCountsToDist $zcounts)))

!(let*
   (($samples (collapse (query 100 kb (: $prf (NextZSample 5.0 2.0 $zv) $tv))))
    ($zcounts
       (fold-flat
          (|-> ($acc $item)
             (let (: $_prf (NextZSample 5.0 2.0 $value) $_tv) $item
                (DistValueCountAcc $acc $value)))
          (PairCounts ())
          $samples)))
   (ParticlePairs (PairCountsToDist $zcounts)))
