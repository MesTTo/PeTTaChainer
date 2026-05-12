!(import! &self petta_chainer)
!(import! &data data_test)

!(compileadd kb (get-atoms &data))

!(car-atom
   (collapse
      (let*
         (((: $pmine (FoldAll (XYZSample (Pair $xy $z)) (Pair $xy $z) (PairCounts ()) DistValueCountAcc -> $counts) $tvmine)
              (once
                 (query 100
                    kb
                    (: $pmine (FoldAll (XYZSample (Pair $xy $z)) (Pair $xy $z) (PairCounts ()) DistValueCountAcc -> $counts) $tvmine))))
          ($jointDist (PairCountsToDist $counts))
          ($_1 (compileadd kb (: mined_joint_model (XYZJointDist $jointDist) (STV 1.0 1.0))))
          ($_2 (compileadd kb (: predict_case_a (PredictInput caseA 10.0 100.0) (STV 1.0 1.0))))
          ($_3 (compileadd kb (: predict_case_b (PredictInput caseB 10.0 2.0) (STV 1.0 1.0))))
          ((: $prfa (PredictedZDist caseA $zdistA) $tva)
             (once (query 100 kb (: $prfa (PredictedZDist caseA $zdistA) $tva))))
          ((: $prfb (PredictedZDist caseB $zdistB) $tvb)
             (once (query 100 kb (: $prfb (PredictedZDist caseB $zdistB) $tvb)))))
         ((ParticlePairs $jointDist) (ParticlePairs $zdistA) (ParticlePairs $zdistB)))))
