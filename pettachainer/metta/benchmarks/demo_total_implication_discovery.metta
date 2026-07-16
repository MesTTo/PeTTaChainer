!(import! &self petta_chainer)

; Measures total-implication discovery across candidate predicates and evidence sizes.

(= (TIBenchListCount ()) 0)
(= (TIBenchListCount (cons $_x $tail)) (+ 1 (TIBenchListCount $tail)))

(= (TIBenchPred $idx) (atom_concat TIPred $idx))
(= (TIBenchTargetPred $kb) (atom_concat TITarget $kb))
(= (TIBenchObj $kb $idx) (ti-obj $kb $idx))
(= (TIBenchQueryObj $kb) (ti-query $kb))

(= (TotalEvidenceOr none $tv) $tv)
(= (TotalEvidenceOr $left $right) (OrFormula $left $right))
(= (TotalEvidenceTv none) (STV 0.0 0.0))
(= (TotalEvidenceTv $tv) $tv)
(= (TotalEvidenceAcc (TotalEvidenceTvs $pos-tv $neg-tv) (EvidenceCase pos $tv))
   (TotalEvidenceTvs (TotalEvidenceOr $pos-tv $tv) $neg-tv))
(= (TotalEvidenceAcc (TotalEvidenceTvs $pos-tv $neg-tv) (EvidenceCase neg $tv))
   (TotalEvidenceTvs $pos-tv (TotalEvidenceOr $neg-tv $tv)))
(= (TotalEvidenceMpFormula $atv $evidence-tvs)
   (if (= $evidence-tvs (TotalEvidenceTvs none none))
      (empty)
      (let (TotalEvidenceTvs $pos-tv $neg-tv) $evidence-tvs
         (TotalMpFormula $atv (TotalEvidenceTv $pos-tv) (TotalEvidenceTv $neg-tv)))))

!(add-to-kb
   (rules
      (((($p1 $x) (kb $ctx $vars) $p1prf $p1tv)
        (($p2 $x) (kb $ctx $vars) $p2prf $p2tv)
        (CPU AndFormula ($p1tv $p2tv) $case-tv))
       |-
       ((TotalEvidence pos $p1 $p2 $x $case-tv)
          (kb $ctx $vars)
          (total-pos (rule-proof conjunction $p1prf $p2prf))
          $case-tv))))

!(add-to-kb
   (rules
      (((($p1 $x) (kb $ctx $vars) $p1prf $p1tv)
        (CPU NotFormula ($p1tv) $not-p1tv)
        (($p2 $x) (kb $ctx $vars) $p2prf $p2tv)
        (CPU AndFormula ($not-p1tv $p2tv) $case-tv))
       |-
       ((TotalEvidence neg $p1 $p2 $x $case-tv)
          (kb $ctx $vars)
          (total-neg (rule-proof conjunction (negated $p1prf) $p2prf))
          $case-tv))))

!(add-to-kb
   (rules
      (((($p1 $y) (kb $ctx $vars) $apr $atv)
        (CPU NotEqual ($p1 $p2) true)
        (CPU FoldAllCompiled
           (kb
              (TotalEvidence $case $p1 $p2 $x $case-tv)
              (extract-value
                 (TotalEvidence $case $p1 $p2 $x $case-tv)
                 (EvidenceCase $case $case-tv))
              (TotalEvidenceTvs none none)
              TotalEvidenceAcc
              identity
              result-tv)
           $evidence-tvs)
        (CPU TotalEvidenceMpFormula ($atv $evidence-tvs) $btv))
       |-
       (($p2 $y)
          (kb $ctx $vars)
          (ii_total $apr cpu)
          $btv))))

(= (TIBenchAddTarget $kb $idx)
   (let*
      (($obj (TIBenchObj $kb $idx))
       ($target-pred (TIBenchTargetPred $kb)))
      (compileadd kb
         (: (ti-target $idx)
            ($target-pred $obj)
            (STV 0.9 0.9)))))

(= (TIBenchAddTargets $kb $idx)
   (if (<= $idx 0) done
      (let $_ (TIBenchAddTarget $kb $idx)
         (TIBenchAddTargets $kb (- $idx 1)))))

(= (TIBenchAddPredObj $kb $pred-idx $obj)
   (let $pred (TIBenchPred $pred-idx)
      (compileadd kb
         (: (ti-pred $pred-idx $obj)
            ($pred $obj)
            (STV 0.9 0.9)))))

(= (TIBenchAddPredObjects $kb $pred-idx $obj-idx)
   (if (<= $obj-idx 0) done
      (let*
         (($obj (TIBenchObj $kb $obj-idx))
          ($_ (TIBenchAddPredObj $kb $pred-idx $obj)))
         (TIBenchAddPredObjects $kb $pred-idx (- $obj-idx 1)))))

(= (TIBenchAddPred $kb $pred-idx $obj-count)
   (let $_history (TIBenchAddPredObjects $kb $pred-idx $obj-count)
      (let $query-obj (TIBenchQueryObj $kb)
         (TIBenchAddPredObj $kb $pred-idx $query-obj))))

(= (TIBenchAddPreds $kb $pred-idx $obj-count)
   (if (<= $pred-idx 0) done
      (let $_ (TIBenchAddPred $kb $pred-idx $obj-count)
         (TIBenchAddPreds $kb (- $pred-idx 1) $obj-count))))

(= (TIBenchGenerate $kb $pred-count $obj-count)
   (let*
      (($t1 (current-time))
        ($_targets (TIBenchAddTargets $kb $obj-count))
        ($_preds (TIBenchAddPreds $kb $pred-count $obj-count))
        ($t2 (current-time)))
      (tibench-generated
         (kb $kb)
         (predicates $pred-count)
         (objects $obj-count)
         (facts (+ $obj-count (* $pred-count (+ $obj-count 1))))
         (seconds (- $t2 $t1)))))

(= (TIBenchQuery $kb $pred-count $steps)
   (let*
      (($t1 (current-time))
        ($query-obj (TIBenchQueryObj $kb))
        ($target-pred (TIBenchTargetPred $kb))
        ($results
           (collapse
              (query $steps kb
                 (: $prf ($target-pred $query-obj) $tv))))
        ($t2 (current-time)))
      (tibench-query
         (kb $kb)
         (candidate-predicates $pred-count)
         (steps $steps)
         (seconds (- $t2 $t1))
         (answers (TIBenchListCount $results)))))

(= (TIBenchCase $kb $pred-count $obj-count $steps)
   ((TIBenchGenerate $kb $pred-count $obj-count)
    (TIBenchQuery $kb $pred-count $steps)))

!(TIBenchCase tiBench05x10 5 10 80)
!(TIBenchCase tiBench10x10 10 10 120)
!(TIBenchCase tiBench20x10 20 10 180)
