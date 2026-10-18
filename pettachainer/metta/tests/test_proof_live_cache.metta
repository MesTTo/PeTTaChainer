; Purpose: checks that the liveness caches memoise liveness. After a query that writes aggregate
; rows, each cached row is the only one for its proof, the chainer's own lookups find it, a warm
; cache answers what an emptied one recomputes, and asking again adds no row. A new aggregate row
; or a changed current proof empties the caches, and a changed pending score does not.

!(import! &self petta_chainer)

; superpose takes its argument as the tuple of alternatives on both engines, so each list a
; function answers is bound before superpose spreads it.
(= (LiveRows) (collapse (get-atoms &proof_live_cache)))
(= (StoredPids) (collapse (match &proof ($pid $_gid $_output $_kind $_score $_ev $_children) $pid)))
(= (GoalIds) (collapse (match &goal ($gid $_depth $_goal $_expanded $_pending) $gid)))
(= (ProofLiveness)
   (let $pids (StoredPids) (collapse (let $pid (superpose $pids) ($pid (proof-live? $pid))))))
(= (GoalLiveness)
   (let $gids (GoalIds) (collapse (let $gid (superpose $gids) ($gid (goal-live-proof-ids $gid))))))

!(compileadd liveKb (: prf (Score A 1) (STV 1.0 1.0)))
!(compileadd liveKb (: prf (Score B 2) (STV 1.0 1.0)))
!(compileadd liveKb (: prf (Score C 3) (STV 1.0 1.0)))
!(compileadd liveKb
   (: foldRule
      (Implication (Premises (FoldAll (Score $name $n) $n 0 (|-> ($acc $elem) (+ $acc $elem)) -> $total))
         (Conclusions (ScoreTotal $total)))
      (STV 1.0 1.0)))

!(test (query 30 liveKb (: $prf (ScoreTotal $x) $tv))
   (: (rule-proof foldRule (rule-proof foldall prf prf prf)) (ScoreTotal 6) (STV 1.0 1.0)))

; The query left rows, and no proof has two.
; am[verifies a-pc-live-cache-pure-memo-1018@d3f8a0]
!(test
   (let $rows (LiveRows)
      ((> (size-atom $rows) 0) (== (size-atom $rows) (size-atom (unique-atom $rows)))))
   (true true))

; The chainer's own lookup finds every row the caches hold, and there are proofs and goals to ask.
; am[verifies a-pc-live-cache-pure-memo-1018@d3f8a0]
!(test
   (let $rows (LiveRows)
      ((unique-atom
          (collapse
             (let ($epoch $pid $alive) (superpose $rows)
                (== (collapse (cached-proof-live? $pid)) ($alive)))))
       (> (size-atom (ProofLiveness)) 0)
       (> (size-atom (GoalLiveness)) 0)))
   ((true) true true))

; A warm cache answers what an emptied cache recomputes, for every proof and every goal.
; am[verifies a-pc-live-cache-pure-memo-1018@d3f8a0]
!(test
   (let* (($warm-proofs (ProofLiveness))
          ($warm-goals (GoalLiveness))
          ($emptied (invalidate-proof-live-caches))
          ($fresh-proofs (ProofLiveness))
          ($fresh-goals (GoalLiveness)))
      ((== $warm-proofs $fresh-proofs) (== $warm-goals $fresh-goals)))
   (true true))

; Every stored proof has its row now, so asking again adds none.
; am[verifies a-pc-live-cache-pure-memo-1018@d3f8a0]
!(test
   (let* (($before (size-atom (LiveRows)))
          ($again (ProofLiveness))
          ($after (size-atom (LiveRows))))
      (== $before $after))
   true)

; A new aggregate row and a changed current proof each empty the caches and advance the epoch;
; a changed pending score keeps them.
; am[verifies a-pc-live-cache-pure-memo-1018@d3f8a0]
!(test
   (let* (($reset (chainer-reset!))
          ($added (add-aggregate-row! liveAgg liveChild liveArgs 0.5))
          ($epoch (proof-live-cache-epoch))
          ($cached (cache-proof-live! 5 true))
          ($pending (replace-aggregate-row! (liveAgg liveChild liveArgs 0.5 0.0 ()) 0.5 ()))
          ($kept (collapse (cached-proof-live? 5)))
          ($current (replace-aggregate-row! (liveAgg liveChild liveArgs 0.5 0.5 ()) 0.5 (7)))
          ($emptied (collapse (cached-proof-live? 5)))
          ($next-epoch (proof-live-cache-epoch)))
      ($epoch $kept $emptied (== $next-epoch (+ $epoch 1)) (collapse (get-atoms &aggregate))))
   (1 (true) () true ((liveAgg liveChild liveArgs 0.5 0.5 (7)))))
