!(import! &self chainer/compile)

!(use-module! heaps)

!(import_prolog_function (superpose (empty_heap add_to_heap get_from_heap heap_size)))
!(assertzPredicate (Predicate (arity empty_heap 1)))
!(assertzPredicate (Predicate (arity add_to_heap 4)))
!(assertzPredicate (Predicate (arity get_from_heap 4)))
!(assertzPredicate (Predicate (arity heap_size 2)))

!(import! &self chainer/chainer_utils)
!(import! &self chainer/forward_chainer)
!(import! &self chainer/dist_formulas)
!(import! &self chainer/tv_formulas)
!(import! &self chainer/compiled_query_runtime)
!(import! &self chainer/backward_proof_store)
!(import! &self chainer/backward_chainer)
!(import! &self context/context_from_kb)
!(import! &self chainer/proof_structure_audit)

!(bind! &kb_source_events (new-space))

(= (register-kb-source-event! $kb $kind $payload)
   (let $copy (copy_term $payload)
      (add-atom &kb_source_events ($kb $kind $copy))))

(= (register-raw-compiled-source! $expr)
   (let $kb (compiled-expr-kbid $expr)
      (if (== $kb ()) ()
         (register-kb-source-event! $kb raw $expr))))

(= (add-compiled-to-kb $expr) (kb-add-expr live $expr))

(= (add-to-kb $expr)
   (let $_source (register-raw-compiled-source! $expr)
      (add-compiled-to-kb $expr)))

(= (materialize-stmt-lambdas $term)
   (if (is-var $term) $term
      (if (is-expr $term)
         (if (== (car-atom $term) |->) (eval $term)
            (cons (materialize-stmt-lambdas (car-atom $term))
               (map-flat materialize-stmt-lambdas (cdr-atom $term))))
         $term)))

(= (compileadd-materialized $kb $stmt)
   (let*
      (($_evidence (register-user-rule-evidence! $kb $stmt))
        ($atoms (collapse (mm2compile $kb $stmt)))
        ($iatoms (list_to_set (map-flat internalize-proof-structure $atoms)))
        ($eatoms (map-flat externalize-proof-structure $iatoms))
        ($_index (index-source-implication $kb $stmt))
        ($_ (collapse (foreach-flat add-compiled-to-kb $iatoms))))
      (superpose
         $eatoms)))

(= (compileadd $kb $stmt)
   (let*
      (($stmt1 (materialize-stmt-lambdas $stmt))
       ($outputs (collapse (compileadd-materialized $kb $stmt1)))
       ($_source (register-kb-source-event! $kb source $stmt1)))
      (superpose $outputs)))

(= (source-statement-name-equal? $statement $name)
   (if (= $statement (: $stored-name $_type $_tv))
      (=alpha $stored-name $name)
      false))

(= (source-statements $kb)
   (match &kb_source_events ($kb source $statement)
      (copy_term $statement)))

(= (kb-source-events $kb)
   (collapse
      (match &kb_source_events ($kb $kind $payload)
         (source-event $kind (copy_term $payload)))))

(= (remove-source-statements-named! $kb $name)
   (let*
      (($matches
          (collapse
             (match &kb_source_events ($kb source $statement)
                (if (source-statement-name-equal? $statement $name)
                   (copy_term $statement)
                   (empty)))))
       ($_removed
          (foreach-flat
             (|-> ($statement)
                (remove-atom &kb_source_events ($kb source $statement)))
             $matches)))
      (length $matches)))

(= (replay-kb-source-event $kb (source-event source $statement))
   (collapse
      (compileadd-materialized $kb (copy_term $statement))))
(= (replay-kb-source-event $_kb (source-event raw $expr))
   (add-compiled-to-kb (copy_term $expr)))

(= (rebuild-compiled-kb! $kb)
   (let*
      (($events (kb-source-events $kb))
       ($_clear (clear-compiled-kb! $kb))
       ($_replay
          (foreach-flat (replay-kb-source-event $kb) $events)))
      true))

(= (remove-compiled-statement $kb $name)
   (if (not (== (extract-vars $name) ())) 0
      (let $removed (remove-source-statements-named! $kb $name)
         (if (<= $removed 0) 0
            (progn
               (rebuild-compiled-kb! $kb)
               $removed)))))
