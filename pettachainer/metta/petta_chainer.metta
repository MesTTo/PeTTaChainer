!(import! &self chainer/compile)
!(import! &self chainer/mining)

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

(= (add-to-kb $expr) (kb-add-expr live $expr))

(= (materialize-stmt-lambdas $term)
   (if (is-var $term) $term
      (if (is-expr $term)
         (if (== (car-atom $term) |->) (eval $term)
            (cons (materialize-stmt-lambdas (car-atom $term))
               (map-flat materialize-stmt-lambdas (cdr-atom $term))))
         $term)))

(= (compileadd $kb $stmt)
   (let*
      (($stmt1 (materialize-stmt-lambdas $stmt))
        ($atoms (collapse (mm2compile $kb $stmt1)))
        ($iatoms (list_to_set (map-flat internalize-proof-structure $atoms)))
        ($eatoms (map-flat externalize-proof-structure $iatoms))
        ($_index (index-source-implication $kb $stmt1))
        ($_ (collapse (foreach-flat add-to-kb $iatoms)))
        ($_ (maybe-process-on-add $kb $stmt1)))
      (superpose
         $eatoms)))

(= (compileadd-mine $kb $stmt)
   (let*
      (($stmt1 (materialize-stmt-lambdas $stmt))
        ($atoms (collapse (mm2compile $kb $stmt1)))
        ($iatoms (list_to_set (map-flat internalize-proof-structure $atoms)))
        ($eatoms (map-flat externalize-proof-structure $iatoms))
        ($_index (index-source-implication $kb $stmt1))
        ($_ (collapse (foreach-flat add-to-kb $iatoms)))
        ($_ (collapse (process-on-add-items $kb $stmt1))))
      $eatoms))
