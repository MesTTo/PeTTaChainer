!(import! &self petta_chainer)

(= (cached-score-ids-at-or-above $minimum)
   (collapse
      (match &rule_expected ($id $_score)
         (if (>= $id $minimum) $id (empty)))))

!(compileadd scoreCacheKb
   (: scoreCacheRule
      (Implication (Premises (ScoreCacheSource)) (Conclusions (ScoreCacheTarget)))
      (STV 0.8 0.6)))

!(test
   (collapse
      (match &rules
         ($id ((ScoreCacheTarget) (scoreCacheKb $_ctx $_vars) $_proof $_tv) $_args)
         (match &rule_expected ($id $score) $score)))
   (1.0 1.0))

!(test
   (let*
      (($_cached (add-atom &rule_expected (manualScoreCache 0.125)))
       ($args
          (((ScoreCacheSource) (scoreCacheKb MAIN Nil) sourceProof (STV 1.0 0.9))
           (CPU MpFormula ((STV 1.0 0.6) (STV 1.0 0.9)) $resultTv))))
      ((rule-expected-score manualScoreCache
          ((ScoreCacheTarget) (scoreCacheKb MAIN Nil) $proof $tv)
          $args)
       (rule-expected-score manualScoreCache
          ((ScoreCacheTarget) (scoreCacheKb MAIN Nil) boundProof (STV 1.0 0.9))
          $args)))
   (0.125 0.6))

!(remove-atom &rule_expected (manualScoreCache 0.125))

!(test
   (let*
      (($old-ids
          (collapse
             (match &rules
                ($id ((ScoreCacheTarget) (scoreCacheKb $_ctx $_vars) $_proof $_tv) $_args)
                $id)))
       ($_removed (remove-compiled-statement scoreCacheKb scoreCacheRule))
       ($stale
          (collapse
             (match &rule_expected ($id $_score)
                (if (is-member $id $old-ids) $id (empty))))))
      (length $stale))
   0)

!(clear-temp-query-adds)

!(kb-add-expr temp
   (rules
      ((((TempScoreSource) (tempScoreKb MAIN Nil) tempSource (STV 1.0 0.9))
        (CPU MpFormula ((STV 1.0 0.6) (STV 1.0 0.9)) $resultTv))
       |-
       ((TempScoreTarget) (tempScoreKb MAIN Nil) tempRule $resultTv))))

!(test (length (cached-score-ids-at-or-above 1000000000)) 1)

!(clear-temp-query-adds)

!(test (length (cached-score-ids-at-or-above 1000000000)) 0)
