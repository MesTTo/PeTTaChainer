(= (kb-add-atom live $space $expr) (add-atom $space $expr))
(= (kb-add-atom temp $space $expr) (progn (add-atom $space $expr) (add-atom &temp_query_ref (temp_row $space $expr))))

(= (kb-add-prem $backend $id $idx $prem)
   (let $key (forward-indexable-premise-key $prem)
      (progn (if (== $key ()) () (kb-add-atom $backend &prem_index ($key $prem $id $idx))) (+ $idx 1))))

(= (kb-add-ccl-head-index $backend $id $ccls)
   (let $key (forward-indexable-premise-key $ccls)
      (if (== $key ()) () (kb-add-atom $backend &ccls_head_index ($key $id)))))

(= (wildcard-premise-index-key $type)
   (if (is-var $type) ()
      (if (contains-hash? $type)
         (if (is-expr $type)
            (let $head (car-atom $type) (if (== $head #) wildcard_any (wildcard_premise_head $head)))
            wildcard_any)
         ())))

(= (kb-add-wildcard-premise-index $backend $expr)
   (if (= $expr ($type $kb $prf $tv))
      (let $key (wildcard-premise-index-key $type)
         (if (== $key ()) ()
            (progn
               (kb-add-atom $backend &wildcard_premise_context ($kb))
               (kb-add-atom $backend &wildcard_premise_index ($key $kb $type $prf $tv)))))
      ()))

(= (next-rule-id $backend)
   (if (== $backend live)
      (next-search-id ruleid)
      (+ 1000000000 (next-search-id bwd_tmp_ruleid))))

(= (store-rule-expected-score! $backend $id $args)
   (let $hits (collapse (premises-expected-confidence (copy_term $args)))
      (if (== $hits ()) ()
         (kb-add-atom $backend &rule_expected ($id (car-atom $hits))))))

(= (compiled-row-kbid $row)
   (if (= $row ($_type ($kbid $_ctx $_vars) $_proof $_tv)) $kbid ()))

(= (compiled-expr-kbid $expr)
   (if (= $expr (rules ($_args |- $ccls)))
      (compiled-row-kbid $ccls)
      (compiled-row-kbid $expr)))

(= (kb-add-expr $backend $expr)
   (if (= $expr (rules ($args |- $ccls)))
      (let*
         (($id (next-rule-id $backend))
           ($kbid (compiled-row-kbid $ccls))
           ($_1 (fold-flat (kb-add-prem $backend $id) 0 $args))
           ($_2 (kb-add-atom $backend &ccls_index ($ccls $id)))
           ($_3 (kb-add-ccl-head-index $backend $id $ccls))
           ($_4 (kb-add-atom $backend &rules ($id $ccls $args)))
           ($_expected (store-rule-expected-score! $backend $id $args))
           ($_kb-index
              (if (and (== $backend live) (not (== $kbid ())))
                 (kb-add-atom $backend &rule_kb_index ($kbid $id))
                 ()))
           ($_5 (if (== $backend live) (mark-forward-agenda-dirty $ccls) ())))
         ())
      (progn
         (kb-add-atom $backend &kb $expr)
         (kb-add-wildcard-premise-index $backend $expr)
         (if (== $backend live) (mark-forward-agenda-dirty $expr) ()))))

(= (clear-temp-query-adds)
   (progn
      (collapse
         (match &temp_query_ref (temp_row $space $expr)
            (progn (remove-atom $space $expr) (remove-atom &temp_query_ref (temp_row $space $expr)))))
      true))

(= (inject-compiled-adds $adds)
   (if (= $adds ())
      true
      (progn
         (foreach-flat (kb-add-expr temp) $adds)
         true)))

(= (remove-rule-premise-indexes! $id)
   (let $_removed
      (collapse
         (match &prem_index ($key $premise $id $index)
            (remove-atom &prem_index ($key $premise $id $index))))
      ()))

(= (remove-rule-kb-indexes! $id)
   (let $_removed
      (collapse
         (match &rule_kb_index ($kbid $id)
            (remove-atom &rule_kb_index ($kbid $id))))
      ()))

(= (remove-rule-expected-scores! $id)
   (let $_removed
      (collapse
         (match &rule_expected ($id $score)
            (remove-atom &rule_expected ($id $score))))
      ()))

(= (remove-live-rule! $id)
   (let $_rows
      (collapse
         (match &rules ($id $conclusion $premises)
            (let*
               (($_premise-indexes (remove-rule-premise-indexes! $id))
                ($_conclusion-index
                   (remove-atom &ccls_index ($conclusion $id)))
                ($head-key (forward-indexable-premise-key $conclusion))
                ($_head-index
                   (if (== $head-key ()) ()
                      (remove-atom &ccls_head_index ($head-key $id))))
                ($_rule (remove-atom &rules ($id $conclusion $premises))))
               ())))
      (let $_expected (remove-rule-expected-scores! $id)
         (remove-rule-kb-indexes! $id))))

(= (remove-kb-rules! $kb)
   (let $ids
      (list_to_set
         (collapse
            (match &rule_kb_index ($kb $id) $id)))
      (foreach-flat remove-live-rule! $ids)))

(= (remove-wildcard-indexes-for-fact! ($type $kb $proof $tv))
   (let $_removed
      (collapse
         (match &wildcard_premise_index ($key $kb $type $proof $tv)
            (remove-atom &wildcard_premise_index
               ($key $kb $type $proof $tv))))
      ()))

(= (remove-kb-fact! $fact)
   (let $_wildcard (remove-wildcard-indexes-for-fact! $fact)
      (remove-atom &kb $fact)))

(= (remove-kb-facts! $kb)
   (let $facts
      (collapse
         (match &kb ($type ($kb $ctx $vars) $proof $tv)
            (copy_term ($type ($kb $ctx $vars) $proof $tv))))
      (foreach-flat remove-kb-fact! $facts)))

(= (remove-kb-wildcard-indexes! $kb)
   (let $_rows
      (collapse
         (match &wildcard_premise_index
            ($key ($kb $ctx $vars) $type $proof $tv)
            (remove-atom &wildcard_premise_index
               ($key ($kb $ctx $vars) $type $proof $tv))))
      (let $_contexts
         (collapse
            (match &wildcard_premise_context (($kb $ctx $vars))
               (remove-atom &wildcard_premise_context (($kb $ctx $vars)))))
         ())))

(= (remove-kb-compiler-metadata! $kb)
   (let $_implications
      (collapse
         (match &implication_index
            ($kb $premise $conclusion $proof $tv)
            (remove-atom &implication_index
               ($kb $premise $conclusion $proof $tv))))
      (let $_evidence
         (collapse
            (match &rule_evidence_names ($kb $name)
               (remove-atom &rule_evidence_names ($kb $name))))
         (let $_templates
            (collapse
               (match &spec_template ($kb $head $statement)
                  (remove-atom &spec_template ($kb $head $statement))))
            (let $_done
               (collapse
                  (match &spec_done ($kb $statement)
                     (remove-atom &spec_done ($kb $statement))))
               ())))))

(= (invalidate-forward-kb-after-rebuild $kb)
   (let $_generation (forward-next-agenda-gen $kb)
      (progn
         (forward-save-agenda $kb (empty_heap))
         (forward-set-agenda-scope $kb (kb $kb))
         (forward-set-agenda-dirty $kb true)
         true)))

(= (clear-compiled-kb! $kb)
   (progn
      (remove-kb-rules! $kb)
      (remove-kb-facts! $kb)
      (remove-kb-wildcard-indexes! $kb)
      (remove-kb-compiler-metadata! $kb)
      (invalidate-forward-kb-after-rebuild $kb)
      true))

(= (drop-empty-results $results)
   (case $results (
      (() ())
      ((cons () $rest) (drop-empty-results $rest))
      ((cons $head $rest) (cons $head (drop-empty-results $rest))))))

(= (query $steps $kb $stmt)
   (let*
      (((compiled-query $goal $adds) (mm2compileQuery $kb $stmt))
        ($_clear-temp-before (clear-temp-query-adds))
        ($_ (inject-compiled-adds $adds))
        ($raw-results (collapse (reduce (chainer $steps $goal))))
        ($results (drop-empty-results $raw-results))
        ($eres (map-flat externalize-proof-structure $results))
        ($pres (map-flat pretty $eres))
        ($_clear-temp-after (clear-temp-query-adds)))
      (if (== $pres ()) (empty) (superpose $pres))))

(= (query-materialize $steps $kb $stmt)
   (let*
      (((compiled-query $goal $adds) (mm2compileQuery $kb $stmt))
        ($_clear-temp-before (clear-temp-query-adds))
        ($_ (inject-compiled-adds $adds))
        ($raw-results (collapse (reduce (chainer-materialize $steps $goal))))
        ($results (drop-empty-results $raw-results))
        ($eres (map-flat externalize-proof-structure $results))
        ($pres (map-flat pretty $eres))
        ($_clear-temp-after (clear-temp-query-adds)))
      (if (== $pres ()) (empty) (superpose $pres))))
