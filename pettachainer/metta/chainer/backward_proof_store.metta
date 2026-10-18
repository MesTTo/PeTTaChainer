(= (normalize-proof-output-atom-kind $term $pid)
   (if (= $term ($type ($kbid $_ctx $_vars) $_prf $tv)) ($type ($kbid $_ctx $_vars) (proof-ref $pid) $tv)
      $term))

(= (proof-output-atom-kind (leaf $term) $pid) (normalize-proof-output-atom-kind $term $pid))
(= (proof-output-atom-kind (rule $term) $pid) (normalize-proof-output-atom-kind $term $pid))
(= (proof-output-atom-kind (aggregate $term) $_pid) $term)
(= (proof-output-atom-kind (merged $term) $_pid) $term)

(= (proof-output-atom $pid) (match &proof ($pid $_gid $output $_kind $_score $_ev $_children) $output))

(= (candidate-output-key $term)
   (case $term (
      (($type $kb $_prf $_tv) ($type $kb))
      ($other $other))))

(= (proof-output-key-by-id $pid)
   (candidate-output-key (proof-output-atom $pid)))

(= (materialize-proof-refs $term)
   (if (is-expr $term)
      (if (is-var (car-atom $term))
         (cons (car-atom $term) (map-flat materialize-proof-refs (cdr-atom $term)))
         (if (== (car-atom $term) proof-ref)
            (materialize-proof-refs (materialize-proof (car-atom (cdr-atom $term))))
            (cons (materialize-proof-refs (car-atom $term)) (map-flat materialize-proof-refs (cdr-atom $term)))))
      $term))

(= (materialize-result-atom $atom)
   (if (= $atom ($type $kb $prf $tv)) ($type $kb (materialize-proof-refs $prf) $tv) $atom))

(= (materialize-proof-kind (leaf $raw) $_pid)
   (if (= $raw (CPU $_fun $_args $_res)) cpu (if (= $raw ($_type ($_kbid $_ctx $_vars) $prf $_tv)) $prf $raw)))
(= (aggregate-proof-label (CPU FoldAllCompiled $args $_res))
   (if (= $args ($_kb $_pattern $_extractor $_init OrFormula $_finish $_tv-mode))
      disjunction
      foldall))
(= (aggregate-proof-label (CPU GroupedFoldAllCompiled $args $_res))
   (if (= $args ($_kb $_pattern $_group $_extractor $_init OrFormula $_finish $_tv-mode))
      disjunction
      foldall))
(= (proof-ref-list ()) ())
(= (proof-ref-list (cons $pid $rest)) (cons (proof-ref $pid) (proof-ref-list $rest)))
(= (aggregate-child-proof-tokens ()) ())
(= (aggregate-child-proof-tokens (cons $pid $rest))
   (let $output (proof-output-atom $pid)
      (if (or (= $output (CPU FoldAllCompiled $_args $_res)) (= $output (CPU GroupedFoldAllCompiled $_gargs $_gres)))
         (cons (materialize-proof $pid) (aggregate-child-proof-tokens $rest))
         (aggregate-child-proof-tokens $rest))))
(= (replace-cpu-proof-token-list () $proofs) (() $proofs))
(= (replace-cpu-proof-token-list (cons $head $tail) $proofs)
   (let*
      ((($new-head $proofs1) (replace-cpu-proof-token $head $proofs))
       (($new-tail $proofs2) (replace-cpu-proof-token-list $tail $proofs1)))
      ((cons $new-head $new-tail) $proofs2)))
(= (replace-cpu-proof-token $term $proofs)
   (if (is-var $term)
      ($term $proofs)
      (if (== $term cpu)
         (if (= $proofs (cons $proof $rest)) ($proof $rest) (cpu ()))
         (if (is-expr $term)
            (let* ((($new-list $rest-proofs) (replace-cpu-proof-token-list $term $proofs)))
               ($new-list $rest-proofs))
            ($term $proofs)))))
(= (materialize-rule-proof-token $prf $pid)
   (let*
      (($base-prf (materialize-proof-refs $prf))
       ($aggregate-proofs (aggregate-child-proof-tokens (proof-children-by-id $pid)))
       (($new-prf $_unused) (replace-cpu-proof-token $base-prf $aggregate-proofs)))
      $new-prf))
(= (materialize-proof-kind (aggregate $raw) $pid)
   (let $children (proof-children-by-id $pid)
      (if (== $children ()) cpu
         (cons rule-proof
            (cons (aggregate-proof-label $raw)
               (map-flat materialize-proof-refs (proof-ref-list $children)))))))
(= (materialize-proof-kind (merged $output) $_pid)
   (if (= $output ($_type $_kb $prf $_tv)) (materialize-proof-refs $prf) $output))
(= (rule-kind-proof-token $term)
   (if (is-expr $term)
      (let $tail1 (cdr-atom $term)
         (if (== $tail1 ()) $term
            (let $tail2 (cdr-atom $tail1)
               (if (== $tail2 ()) $term
                  (car-atom $tail2)))))
      $term))
(= (materialize-rule-proof-expression $rule-prf)
   (if (is-expr $rule-prf)
      (if (is-var (car-atom $rule-prf))
         (if (== (cdr-atom $rule-prf) ())
            $rule-prf
            (car-atom (cdr-atom $rule-prf)))
         (cons rule-proof
            (cons (car-atom $rule-prf) (cdr-atom $rule-prf))))
      $rule-prf))
(= (materialize-proof-kind (rule $term) $pid)
   (let $prf (rule-kind-proof-token $term)
      (if (== $prf $term) $term
         (let $rule-prf (materialize-rule-proof-token $prf $pid)
            (materialize-rule-proof-expression $rule-prf)))))

(= (materialize-proof $pid)
   (match &proof ($pid $_gid $_output $kind $_score $_ev $_children)
      (materialize-proof-kind $kind $pid)))

(= (goal-proof-ids $gid)
   (collapse (match &proof ($pid $gid $_output $_kind $_score $_ev $_children) $pid)))

(= (proof-goal-id $pid)
   (match &proof ($pid $gid $_output $_kind $_score $_ev $_children) $gid))

(= (proof-children-by-id $pid)
   (match &proof ($pid $_gid $_output $_kind $_score $_ev $children) $children))

(= (proof-kind-by-id $pid)
   (match &proof ($pid $_gid $_output $kind $_score $_ev $_children) $kind))

(= (materializable-proof-kind? (rule $_term)) true)
(= (materializable-proof-kind? $_kind) false)

(= (materializable-proof-output? ($type ($_kbid MAIN Nil) $_prf $_tv))
   (and (== (extract-vars $type) ()) (not (contains-hash? $type))))
(= (materializable-proof-output? $_output) false)

(= (materialize-proof-node-to-kb $pid)
   (let*
      (($kind (proof-kind-by-id $pid))
       ($output (proof-output-atom $pid)))
      (if (and (materializable-proof-kind? $kind) (materializable-proof-output? $output))
         (let $fact (materialize-result-atom $output)
            (progn
               (forward-fact-upsert (empty_heap) $fact)
               (mark-forward-agenda-dirty $fact)
               true))
         true)))

(= (materialize-proof-tree-to-kb $pid)
   (let $_children (materialize-proof-list-to-kb (proof-children-by-id $pid))
      (materialize-proof-node-to-kb $pid)))

(= (materialize-proof-list-to-kb ()) true)
(= (materialize-proof-list-to-kb (cons $pid $rest))
   (let $_head (materialize-proof-tree-to-kb $pid)
      (materialize-proof-list-to-kb $rest)))

(= (materialize-goal-proofs-to-kb $gid)
   (materialize-proof-list-to-kb (goal-live-proof-ids $gid)))

(= (proof-live-cache-epoch)
   (let $n (chainer-cell-get bwd_live_epoch) (if-error $n 0 $n)))

(= (clear-proof-live-caches)
   (progn
      (remove-all-atoms &proof_live_cache)
      (remove-all-atoms &goal_live_cache)
      ()))

(= (invalidate-proof-live-caches)
   (let $epoch (proof-live-cache-epoch)
      (progn
         (chainer-cell-write! bwd_live_epoch (+ $epoch 1))
         (clear-proof-live-caches))))

; The liveness caches memoise proof-live-compute and goal-live-proof-ids-compute within one
; epoch: each row holds a value those computed, and every change to what they read, a stored
; proof, a new aggregate row or a changed current proof, empties both. A match pattern and the
; atom of remove-atom hold a call as data on PeTTa and pymetta alike, so a pattern written
; ((proof-live-cache-epoch) $pid $alive) never meets the (0 $pid $alive) rows the stores keep;
; every operation binds the epoch first.
; am[implements a-pc-live-cache-pure-memo-1018@d3f8a0]
(= (cache-proof-live! $pid $alive)
   (let $epoch (proof-live-cache-epoch)
      (chainer-add-atom &proof_live_cache ($epoch $pid $alive))))

; am[implements a-pc-live-cache-pure-memo-1018@d3f8a0]
(= (cached-proof-live? $pid)
   (let $epoch (proof-live-cache-epoch)
      (match &proof_live_cache ($epoch $pid $alive) $alive)))

; am[implements a-pc-live-cache-pure-memo-1018@d3f8a0]
(= (goal-live-cache-store! $gid $pids)
   (let $epoch (proof-live-cache-epoch)
      (chainer-add-atom &goal_live_cache ($epoch $gid $pids))))

; am[implements a-pc-live-cache-pure-memo-1018@d3f8a0]
(= (goal-live-cache-remove! $gid $pids)
   (let $epoch (proof-live-cache-epoch)
      (remove-atom &goal_live_cache ($epoch $gid $pids))))

; am[implements a-pc-live-cache-pure-memo-1018@d3f8a0]
(= (cached-goal-live-proof-ids $gid)
   (let $epoch (proof-live-cache-epoch)
      (match &goal_live_cache ($epoch $gid $pids) $pids)))

; am[implements a-pc-live-cache-pure-memo-1018@d3f8a0]
(= (append-goal-live-cache! $gid $pid)
   (let*
      (($hits (collapse (once (cached-goal-live-proof-ids $gid)))))
      (if (== $hits ())
         ()
         (let*
            (($pids (car-atom $hits))
             ($npids (append $pids ($pid))))
            (progn
               (goal-live-cache-remove! $gid $pids)
               (goal-live-cache-store! $gid $npids))))))

(= (aggregate-current-pid-live? $current-pid $pid)
   (if (== $current-pid ()) false
      (if (is-expr $current-pid) (is-member $pid $current-pid) (== $current-pid $pid))))

(= (proof-live-compute $pid)
   (let*
      (($gid (proof-goal-id $pid))
       ($current-hits
          (collapse
             (once
                (match &aggregate ($gid $_child $_args $_base $_pending $current-pid)
                   $current-pid)))))
      (if (== $current-hits ())
         (proof-list-live? (proof-children-by-id $pid))
         (aggregate-current-pid-live? (car-atom $current-hits) $pid))))

(= (proof-list-live? ())
   true)
(= (proof-list-live? (cons $pid $rest))
   (and (proof-live? $pid) (proof-list-live? $rest)))

(= (proof-live? $pid)
   (let*
      (($hits (collapse (once (cached-proof-live? $pid)))))
      (if (== $hits ())
         (let*
            (($alive (proof-live-compute $pid))
             ($_cache (cache-proof-live! $pid $alive)))
            $alive)
         (car-atom $hits))))

(= (goal-live-proof-step $acc $pid)
   (if (proof-live? $pid) (append $acc ($pid)) $acc))

(= (goal-live-proof-ids-compute $gid)
   (fold-flat goal-live-proof-step () (goal-proof-ids $gid)))

(= (goal-live-proof-ids $gid)
   (let*
      (($hits (collapse (once (cached-goal-live-proof-ids $gid)))))
      (if (== $hits ())
         (let*
            (($pids-bag (collapse (goal-live-proof-ids-compute $gid))))
            (if (or (== $pids-bag ()) (== (car-atom $pids-bag) ()))
               ()
               (let*
                  (($pids (car-atom $pids-bag))
                   ($_cache (goal-live-cache-store! $gid $pids)))
                  $pids)))
         (car-atom $hits))))

(= (proof-output-groups-add () $pid)
   ((proof-output-group (proof-output-key-by-id $pid) ($pid))))
(= (proof-output-groups-add (cons (proof-output-group $key $pids) $rest) $pid)
   (let $pid-key (proof-output-key-by-id $pid)
      (if (=alpha $pid-key $key)
         (cons (proof-output-group $key (append $pids ($pid))) $rest)
         (cons (proof-output-group $key $pids) (proof-output-groups-add $rest $pid)))))

(= (proof-output-groups $pids)
   (fold-flat proof-output-groups-add () $pids))

(= (merge-proof-id-output-step $acc $pid)
   (merge-proof-atoms $acc (proof-output-atom $pid)))

; Lifting merge factors common fact evidence out of affine total-MP proofs.
; The residual evidence must be nonempty and disjoint, and re-evaluation must
; reproduce each stored TV. Unsupported proof shapes fall back to normal merge.
(= (lifting-cpu-child? $pid)
   (if (= (proof-output-atom $pid) (CPU $_formula $_args $_result)) true false))

(= (lifting-split-children () $premises $cpus) ($premises $cpus))
(= (lifting-split-children (cons $pid $rest) $premises $cpus)
   (if (lifting-cpu-child? $pid)
      (lifting-split-children $rest $premises (append $cpus ($pid)))
      (lifting-split-children $rest (append $premises ($pid)) $cpus)))

(= (lifting-cpu-formula? $pid $formula)
   (if (= (proof-output-atom $pid) (CPU $formula $_args $_result)) true false))

(= (lifting-standard-cpu-chain? $cpus)
   (case $cpus (
      ((cons $pid ()) (lifting-cpu-formula? $pid TotalMpConclusionFormula))
      ((cons $pid $rest)
         (and
            (lifting-cpu-formula? $pid AndFormula)
            (lifting-standard-cpu-chain? $rest)))
      ($_ false))))

(= (lifting-proof-list-shape? ()) true)
(= (lifting-proof-list-shape? (cons $pid $rest))
   (and (lifting-proof-shape? $pid) (lifting-proof-list-shape? $rest)))

(= (lifting-rule-shape? $pid)
   (let
      ($premises $cpus)
      (lifting-split-children (proof-children-by-id $pid) () ())
      (and
         (not (== $premises ()))
         (and
            (lifting-standard-cpu-chain? $cpus)
            (lifting-proof-list-shape? $premises)))))

(= (lifting-proof-shape? $pid)
   (let $kind (proof-kind-by-id $pid)
      (case $kind (
         ((leaf $_raw) (not (lifting-cpu-child? $pid)))
         ((rule $_raw) (lifting-rule-shape? $pid))
         ($_ false)))))

(= (lifting-key-in? $_key ()) false)
(= (lifting-key-in? $key (cons $head $rest))
   (if (=alpha $key $head) true (lifting-key-in? $key $rest)))

(= (lifting-and-fold $tvs)
   (case $tvs (
      ((cons $tv ()) $tv)
      ((cons $tv $rest) (AndFormula $tv (lifting-and-fold $rest)))
      ($_ no-tv))))

(= (lifting-last $items)
   (case $items (
      ((cons $item ()) $item)
      ((cons $_item $rest) (lifting-last $rest))
      ($_ no-item))))

(= (lifting-reeval-list () $_keys $_override) ())
(= (lifting-reeval-list (cons $pid $rest) $keys $override)
   (cons
      (lifting-reeval $pid $keys $override)
      (lifting-reeval-list $rest $keys $override)))

(= (lifting-reeval-rule $pid $keys $override)
   (let*
      ((($premises $cpus)
          (lifting-split-children (proof-children-by-id $pid) () ()))
       ($antecedent-tv
          (lifting-and-fold (lifting-reeval-list $premises $keys $override)))
       ((CPU TotalMpConclusionFormula
            ($source-kb $premise $conclusion $_stored-antecedent $rule-tv $fallback)
            $_stored-result)
          (proof-output-atom (lifting-last $cpus))))
      (reduce
         (reduce
            (TotalMpConclusionFormula
               $source-kb $premise $conclusion $antecedent-tv $rule-tv $fallback)))))

(= (lifting-output-tv $output)
   (case $output (
      ((CPU $_formula $_args $tv) $tv)
      (($_type $_kb $_proof $tv) $tv)
      ($_ no-tv))))

(= (lifting-reeval $pid $keys $override)
   (let*
      (($output (proof-output-atom $pid))
       ($stored-tv (lifting-output-tv $output)))
      (if (lifting-key-in? (candidate-output-key $output) $keys)
         $override
         (case (proof-kind-by-id $pid) (
            ((rule $_raw) (lifting-reeval-rule $pid $keys $override))
            ($_ $stored-tv))))))

(= (lifting-pid-facts $pid)
   (poolable-fact-evidence (snd (proof-stats-by-id $pid))))

(= (lifting-shared-facts (cons $pid $rest))
   (fold-flat
      (|-> ($shared $next-pid)
         (intersection-atom $shared (lifting-pid-facts $next-pid)))
      (lifting-pid-facts $pid)
      $rest))

(= (lifting-fact-key (fact-ev $kb $_proof $type)) ($type $kb))

(= (lifting-shared-keys ()) ())
(= (lifting-shared-keys (cons $fact $rest))
   (cons (lifting-fact-key $fact) (lifting-shared-keys $rest)))

(= (lifting-find-tv-children () $_key) no-tv)
(= (lifting-find-tv-children (cons $pid $rest) $key)
   (let $result (lifting-find-tv $pid $key)
      (if (== $result no-tv)
         (lifting-find-tv-children $rest $key)
         $result)))

(= (lifting-find-tv $pid $key)
   (let $output (proof-output-atom $pid)
      (if (and
            (not (lifting-cpu-child? $pid))
            (=alpha (candidate-output-key $output) $key))
         (lifting-output-tv $output)
         (lifting-find-tv-children (proof-children-by-id $pid) $key))))

(= (lifting-real-conjunction $pid $keys)
   (case $keys (
      ((cons $key ()) (lifting-find-tv $pid $key))
      ((cons $key $rest)
         (AndFormula
            (lifting-find-tv $pid $key)
            (lifting-real-conjunction $pid $rest)))
      ($_ no-tv))))

(= (lifting-residual $pid $keys)
   (total-mp-residual
      (lifting-reeval $pid $keys (STV 1.0 1.0))
      (lifting-reeval $pid $keys (STV 0.0 1.0))))

(= (lifting-revise-residual
      (total-mp-residual $positive-a $negative-a)
      (total-mp-residual $positive-b $negative-b))
   (total-mp-residual
      (mergetvs $positive-a $positive-b)
      (mergetvs $negative-a $negative-b)))

(= (lifting-revise-residuals $pids $keys)
   (case $pids (
      ((cons $pid ()) (lifting-residual $pid $keys))
      ((cons $pid $rest)
         (lifting-revise-residual
            (lifting-residual $pid $keys)
            (lifting-revise-residuals $rest $keys)))
      ($_ no-residual))))

(= (lifting-apply-residual
      $antecedent-tv
      (total-mp-residual $positive $negative))
   (TotalMpFormula $antecedent-tv $positive $negative))

(= (lifting-abs-diff $left $right)
   (let $difference (- $left $right)
      (if (< $difference 0.0) (- 0.0 $difference) $difference)))

(= (lifting-close? $left $right)
   (< (lifting-abs-diff $left $right) 0.000001))

(= (lifting-tv-close? $left $right)
   (if (= $left (STV $left-strength $left-confidence))
      (if (= $right (STV $right-strength $right-confidence))
         (and
            (lifting-close? $left-strength $right-strength)
            (lifting-close? $left-confidence $right-confidence))
         false)
      false))

(= (lifting-residual-evidence $pid $shared)
   (subtraction-atom (snd (proof-stats-by-id $pid)) $shared))

(= (lifting-residual-evidence-list () $_shared) ())
(= (lifting-residual-evidence-list (cons $pid $rest) $shared)
   (cons
      (lifting-residual-evidence $pid $shared)
      (lifting-residual-evidence-list $rest $shared)))

(= (lifting-all-nonempty? ()) true)
(= (lifting-all-nonempty? (cons $items $rest))
   (and (not (== $items ())) (lifting-all-nonempty? $rest)))

(= (lifting-disjoint-from-all? $_evidence ()) true)
(= (lifting-disjoint-from-all? $evidence (cons $other $rest))
   (and
      (== (intersection-atom $evidence $other) ())
      (lifting-disjoint-from-all? $evidence $rest)))

(= (lifting-pairwise-disjoint? ()) true)
(= (lifting-pairwise-disjoint? (cons $evidence $rest))
   (and
      (lifting-disjoint-from-all? $evidence $rest)
      (lifting-pairwise-disjoint? $rest)))

(= (lifting-roundtrip-one? $pid $keys $antecedent-tv)
   (let*
      (($stored-tv (lifting-output-tv (proof-output-atom $pid)))
       ($rebuilt-tv
          (lifting-apply-residual
             $antecedent-tv
             (lifting-residual $pid $keys))))
      (lifting-tv-close? $stored-tv $rebuilt-tv)))

(= (lifting-roundtrips? () $_keys $_antecedent-tv) true)
(= (lifting-roundtrips? (cons $pid $rest) $keys $antecedent-tv)
   (and
      (lifting-roundtrip-one? $pid $keys $antecedent-tv)
      (lifting-roundtrips? $rest $keys $antecedent-tv)))

(= (lifting-shared-tv-consistent? () $_keys $_antecedent-tv) true)
(= (lifting-shared-tv-consistent? (cons $pid $rest) $keys $antecedent-tv)
   (and
      (lifting-tv-close?
         (lifting-real-conjunction $pid $keys)
         $antecedent-tv)
      (lifting-shared-tv-consistent? $rest $keys $antecedent-tv)))

(= (lifting-plan $pids)
   (let $shared (lifting-shared-facts $pids)
      (if (== $shared ()) no-lifting
         (let*
            (($keys (lifting-shared-keys $shared))
             ($antecedent-tv
                (lifting-real-conjunction (car-atom $pids) $keys))
             ($residual-evidence
                (lifting-residual-evidence-list $pids $shared)))
            (if (not (lifting-proof-list-shape? $pids)) no-lifting
               (if (not (lifting-all-nonempty? $residual-evidence)) no-lifting
                  (if (not (lifting-pairwise-disjoint? $residual-evidence)) no-lifting
                     (if (not
                           (lifting-shared-tv-consistent?
                              $pids $keys $antecedent-tv))
                        no-lifting
                        (if (lifting-roundtrips? $pids $keys $antecedent-tv)
                           (lifting-plan-data $keys $antecedent-tv)
                           no-lifting)))))))))

(= (lifting-merge-output $pids (lifting-plan-data $keys $antecedent-tv))
   (let*
      (($residual (lifting-revise-residuals $pids $keys))
       ($merged-tv (lifting-apply-residual $antecedent-tv $residual))
       (($type $kb $_proof $_stored-tv)
          (proof-output-atom (car-atom $pids))))
      ($type $kb
         (cons merge/lifting (proof-ref-list $pids))
         $merged-tv)))

(= (merge-proof-id-output $pids)
   (case $pids (
      (() ())
      ((cons $pid $rest)
         (if (== $rest ())
            (proof-output-atom $pid)
            (let $plan (lifting-plan (cons $pid $rest))
               (if (== $plan no-lifting)
                  (fold-flat merge-proof-id-output-step (proof-output-atom $pid) $rest)
                  (lifting-merge-output (cons $pid $rest) $plan))))))))

(= (proof-ref-ids-list ()) ())
(= (proof-ref-ids-list (cons $head $tail))
   (append (proof-ref-ids $head) (proof-ref-ids-list $tail)))

(= (proof-ref-ids $term)
   (if (= $term (proof-ref $pid)) ($pid)
      (if (== $term ()) ()
         (if (is-expr $term) (proof-ref-ids-list $term) ()))))

(= (proof-id-evidence-step $acc $pid)
   (let ($_score $ev) (proof-stats-by-id $pid)
      (list_to_set (append $acc $ev))))

(= (proof-id-evidence-list $pids)
   (fold-flat proof-id-evidence-step () $pids))

(= (store-merged-proof-representative $gid $output $pids)
   (let*
      (($score (term-confidence $output))
       ($ev (proof-id-evidence-list $pids))
       ($hits
          (collapse
             (once
                (match &proof
                   ($stored-pid (merged-proof-group $gid) $output (merged $output) $score $ev $pids)
                   $stored-pid)))))
      (if (== $hits ())
         (let*
            (($pid (next-pid))
             ($_store
                (chainer-add-atom &proof
                   ($pid (merged-proof-group $gid) $output (merged $output) $score $ev $pids))))
            $pid)
         (car-atom $hits))))

(= (proof-output-group-representative-pid $gid (proof-output-group $_key $pids))
   (case $pids (
      (() ())
      ((cons $pid ()) $pid)
      ((cons $pid $rest)
         (let*
            (($output (merge-proof-id-output (cons $pid $rest)))
             ($referenced-pids (list_to_set (proof-ref-ids $output))))
            (case $referenced-pids (
               (() $pid)
               ((cons $only-pid ()) $only-pid)
               ((cons $_first $_more)
                  (store-merged-proof-representative $gid $output $referenced-pids)))))))))

(= (proof-output-group-representative-pids $_gid ()) ())
(= (proof-output-group-representative-pids $gid (cons $group $rest))
   (cons (proof-output-group-representative-pid $gid $group)
      (proof-output-group-representative-pids $gid $rest)))

(= (goal-merged-proof-ids $gid)
   (proof-output-group-representative-pids $gid
      (proof-output-groups (goal-live-proof-ids $gid))))

(= (proof-output-group-for-key-step $key $pids $pid)
   (if (=alpha (proof-output-key-by-id $pid) $key)
      (append $pids ($pid))
      $pids))

(= (goal-live-proof-ids-for-output-key $gid $key)
   (fold-flat (proof-output-group-for-key-step $key)
      ()
      (goal-live-proof-ids $gid)))

(= (goal-merged-proof-id-for-pid $gid $pid)
   (let $key (proof-output-key-by-id $pid)
      (proof-output-group-representative-pid $gid
         (proof-output-group $key (goal-live-proof-ids-for-output-key $gid $key)))))

(= (goal-results-view $gid)
   (let*
      (($pids-bag (collapse (goal-merged-proof-ids $gid)))
        (($_depth $goal $_expanded $_pending) (reduce (goal-by-id $gid))))
      (if (== $pids-bag ())
         ()
         (if (== (car-atom $pids-bag) ())
            ()
            (if (goal-has-type-vars? $goal)
               (map-flat materialize-result-atom (map-flat proof-output-atom (car-atom $pids-bag)))
               (materialize-result-atom (proof-output-atom (car-atom (car-atom $pids-bag)))))))))

(= (goal-current-output $gid)
   (let ($_depth $goal $_expanded $_pending) (reduce (goal-by-id $gid))
      (if (or (goal-has-type-vars? $goal) (not (goal-has-proof? $gid)))
         no-current
         (case (goal-merged-proof-ids $gid) (
            (() no-current)
            ((cons $pid $_rest) (proof-output-atom $pid)))))))

(= (goal-current-confidence $gid)
   (if (not (goal-has-proof? $gid))
      0.0
      (let $current (goal-current-output $gid)
         (if (== $current no-current) 0.0 (term-confidence $current)))))

(= (leaf-evidence-for-result $result)
   (if (= $result ($type ($kbid $_ctx $_vars) $prf $_tv))
      (if (or (contains-hash? $type) (assumption-proof? $prf))
         ()
         ((fact-ev ($kbid $_ctx $_vars) $prf $type)))
      ()))

(= (proof-overlap-dominates-score? $old-ev $old-score $new-ev $new-score)
   (and (evidence-sets-dependent? $old-ev $new-ev)
      (or (> $old-score $new-score) (and (== $old-score $new-score) (evidence-subset? $new-ev $old-ev)))))

(= (goal-proof-candidate-comparable? false $_outkey $_oldpid) true)
(= (goal-proof-candidate-comparable? true $outkey $oldpid)
   (== (proof-output-key-by-id $oldpid) $outkey))

(= (goal-proof-candidate-step $_open $_outkey $ev $score false $_oldpid) false)
(= (goal-proof-candidate-step $open $outkey $ev $score true $oldpid)
   (if (goal-proof-candidate-comparable? $open $outkey $oldpid)
      (let ($old-score $old-ev) (proof-stats-by-id $oldpid)
         (if (and (== $old-score $score) (== $old-ev $ev)) false
            (if (proof-overlap-dominates-score? $old-ev $old-score $ev $score) false true)))
      true))

(= (goal-has-proof? $gid)
   (not (== (collapse (match &proof ($_pid $gid $_output $_kind $_score $_ev $_children) true)) ())))

(= (classify-goal-proof-candidate-pids $_open $_outkey $_ev $_score ()) true)
(= (classify-goal-proof-candidate-pids $open $outkey $ev $score (cons $pid $rest))
   (if (goal-proof-candidate-step $open $outkey $ev $score true $pid)
      (classify-goal-proof-candidate-pids $open $outkey $ev $score $rest)
      false))

(= (classify-goal-proof-candidate $gid $result $ev $score)
   (if (not (goal-has-proof? $gid))
      true
      (let*
         ((($_depth $goal $_expanded $_pending) (reduce (goal-by-id $gid)))
          ($open (goal-has-type-vars? $goal))
          ($outkey (candidate-output-key $result)))
         (let $pids-bag (collapse (goal-live-proof-ids $gid))
            (if (or (== $pids-bag ()) (== (car-atom $pids-bag) ()))
               true
               (classify-goal-proof-candidate-pids $open $outkey $ev $score (car-atom $pids-bag)))))))

(= (rule-application-name $prf)
   (if (is-expr $prf)
      (let $head (car-atom $prf)
         (if (is-var $head) $head
            (case $head (
               ((inverted $name with $_premise-a $_premise-b)
                  (rule-evidence-base-name $name))
               ((bi-forward $name) (rule-evidence-base-name $name))
               ((bi-backward $name) (rule-evidence-base-name $name))
               ($name (rule-evidence-base-name $name))))))
      (rule-evidence-base-name $prf)))

(= (rule-application-evidence $kb $prf)
   (if (= $kb ($kbid $_ctx $_vars))
      (let $name (rule-application-name $prf)
         (if (is-var $name) ()
            (if (logic-rule? $name) ()
               (if (rule-evidence-registered? $kbid $name)
                  ((rule-ev $kbid $name))
                  ()))))
      ()))

(= (proof-candidate-stored-evidence $candidate)
   (case $candidate (
      ((proof-candidate (rule ($_type $kb $prf $_tv)) $_score $ev $_children)
         (let*
            (($base
                (if (proof-term-contains-negated? $prf)
                   (list_to_set (once (proof-term-evidence-list-mode proof-walk-in-kb $prf)))
                   $ev))
             ($rule-ev (rule-application-evidence $kb $prf)))
            (if (== $rule-ev ()) $base
               (list_to_set (append $base $rule-ev)))))
      ((proof-candidate $_kind $_score $ev $_children) $ev))))

(= (normalize-proof-candidate-evidence (proof-candidate $kind $score $ev $children))
   (proof-candidate $kind $score
      (proof-candidate-stored-evidence (proof-candidate $kind $score $ev $children))
      $children))

; am[implements a-pc-live-cache-pure-memo-1018@d3f8a0]
(= (store-proof-candidate $gid (proof-candidate $kind $score $ev $children))
   (let*
      (($pid (next-pid))
        ($output (proof-output-atom-kind $kind $pid))
        ($stored-ev (proof-candidate-stored-evidence (proof-candidate $kind $score $ev $children)))
        ($_store
           (progn
              (chainer-add-atom &proof ($pid $gid $output $kind $score $stored-ev $children))
              (remove-all-atoms &goal_live_cache)
              ())))
      $pid))

(= (proof-atom-candidate ($type $kb $prf $tv) $ev)
   (proof-candidate (leaf ($type $kb $prf $tv)) (term-confidence ($type $kb $prf $tv)) $ev ()))

(= (leaf-result-candidate $result $ev)
   (if (= $result ($type $_kb $_prf $_tv)) (proof-atom-candidate $result $ev)
      (proof-candidate (leaf $result) (term-confidence $result) $ev ())))

(= (aggregate-result-candidate $result $ev $children)
   (proof-candidate (aggregate $result) (term-confidence $result) $ev $children))

(= (candidate-kind-term (leaf $term)) $term)
(= (candidate-kind-term (rule $term)) $term)
(= (candidate-kind-term (aggregate $term)) $term)
(= (candidate-kind-term (merged $term)) $term)

(= (cyclic-dependency? $pid $gid $cycle-key)
   (and (== (proof-goal-id $pid) $gid)
      (or (== $cycle-key closed-goal)
         (=alpha (proof-output-key-by-id $pid) $cycle-key))))

(= (proof-depends-on-goal-seen? $pid $gid $cycle-key $seen-pids)
   (if (is-member $pid $seen-pids) false
      (or (cyclic-dependency? $pid $gid $cycle-key)
         (fold-flat
            (|-> ($acc $child-pid)
               (or $acc (proof-depends-on-goal-seen? $child-pid $gid $cycle-key (cons $pid $seen-pids))))
            false
            (match &proof ($pid $_proof-gid $_output $_kind $_score $_ev $kids)
               $kids)))))

(= (candidate-cycle-key $gid $kind)
   (let ($_depth $goal $_expanded $_pending) (reduce (goal-by-id $gid))
      (if (goal-has-type-vars? $goal)
         (candidate-output-key (candidate-kind-term $kind))
         closed-goal)))

(= (candidate-is-cyclic-raw? $_gid $_kind ()) false)
(= (candidate-is-cyclic-raw? $gid $kind (cons $pid $pids))
   (let*
      (($cycle-key (candidate-cycle-key $gid $kind))
       ($depends-bag (collapse (proof-depends-on-goal-seen? $pid $gid $cycle-key ())))
       ($depends (if (== $depends-bag ()) false (car-atom $depends-bag))))
      (or $depends (candidate-is-cyclic-raw? $gid $kind $pids))))

(= (candidate-is-cyclic? $gid $kind $pids)
   (let $hits (collapse (candidate-is-cyclic-raw? $gid $kind $pids))
      (if (== $hits ()) false (car-atom $hits))))

(= (wake-proof-commit-heap $agenda $gid $pid)
   (let*
      (($waiters (collapse (match &goal_waiter ($gid $waiter) $waiter)))
       ($representative-pid (goal-merged-proof-id-for-pid $gid $pid))
       ($agenda1
          (fold-flat (|-> ($acc $waiter) (reduce (advance-frontier-waiter-heap $acc $waiter $representative-pid)))
             $agenda
             (foldr-flat frontier-waiter-step () $waiters)))
      ($agenda2
          (fold-flat (|-> ($acc $agg-gid) (reduce (schedule-aggregate-heap $acc $agg-gid)))
             $agenda1
             (foldr-flat aggregate-waiter-step () $waiters))))
      $agenda2))

(= (commit-proof-candidate-heap $agenda $gid $accepted (proof-candidate $kind $score $ev $children))
   (if (== $accepted false) $agenda
      (if (candidate-is-cyclic? $gid $kind $children) $agenda
         (let $pid (store-proof-candidate $gid (proof-candidate $kind $score $ev $children))
            (wake-proof-commit-heap $agenda $gid $pid)))))

(= (aggregate-snapshot-changed? () $_result $_ev)
   true)
(= (aggregate-snapshot-changed? $current-pid $result $ev)
   (let*
      (($current-output (proof-output-atom $current-pid))
       (($_current-score $current-ev) (proof-stats-by-id $current-pid)))
      (or (not (== $current-output $result)) (not (== $current-ev $ev)))))

; am[implements a-pc-live-cache-pure-memo-1018@d3f8a0]
(= (commit-aggregate-snapshot-heap $agenda $agg-gid $result $ev $children)
   (let*
      ((($child-gid $args $base-score $pending $current-pid) (reduce (aggregate-by-id $agg-gid)))
       ($pid (store-proof-candidate $agg-gid (aggregate-result-candidate $result $ev $children)))
       ($_set (replace-aggregate-row! ($agg-gid $child-gid $args $base-score $pending $current-pid) $pending $pid))
       ($nagenda (wake-proof-commit-heap $agenda $agg-gid $pid)))
      $nagenda))
