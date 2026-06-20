; Context generation driven directly from the chainer's stored atoms.
;
; piPLN persistent layer, read through PeTTaChainer's own KB (paper sections 7.1
; persistent evidence state and 9.2 the Kt(phi, C) query). It reads
; (: proof (Head args) (STV s c)) atoms as the context-indexed evidence state,
; turns each into a provenance-tagged evidence packet, derives feature atoms, and
; reuses the scoring/selection/projection from context_generation.metta. STVToEC
; inverts ContextECToSTV: it unwinds a stored truth value back to (EC pos neg)
; counts, the section 7.4 / 8.2 prior unwind.

!(import! &self context/context_generation)

(= (STVToEC (STV $s $c) $prior $cap)
   (if (>= $c 1.0)
      (EC (* $s $cap) (* (- 1.0 $s) $cap))
      (if (<= $c 0.0)
         (EC 0.0 0.0)
         (let $total (min $cap (* $prior (/ $c (- 1.0 $c))))
            (EC (* $s $total) (* (- 1.0 $s) $total))))))

; A stored atom about $entity contributes a feature unless it is the target head,
; an Implication, or below the strength gate. Unary -> (type Head), binary -> (Head value).
(= (KBFeatureAccepts $head $target-head $s)
   (and (>= $s 0.5) (and (not (== $head Implication)) (not (== $head $target-head)))))

(= (KBUnaryFeatures $space $entity $target-head)
   (collapse
      (match $space (: $_proof ($head $entity) (STV $s $_c))
         (if (KBFeatureAccepts $head $target-head $s) (type $head) (empty)))))

(= (KBBinaryFeatures $space $entity $target-head)
   (collapse
      (match $space (: $_proof ($head $entity $value) (STV $s $_c))
         (if (KBFeatureAccepts $head $target-head $s) ($head $value) (empty)))))

(= (KBEntityFeatures $space $entity $target-head)
   (fold-flat
      ContextAddFeature
      (KBUnaryFeatures $space $entity $target-head)
      (KBBinaryFeatures $space $entity $target-head)))

; Union the entity features over every argument position of a statement.
(= (KBStatementFeatureStep $space $target-head $acc $entity)
   (fold-flat ContextAddFeature $acc (KBEntityFeatures $space $entity $target-head)))

(= (KBStatementFeatures $space $statement $target-head)
   (fold-flat
      (KBStatementFeatureStep $space $target-head)
      ()
      (cdr-atom $statement)))

; Section 7.1: build a provenance-tagged evidence packet (the storage unit of the
; piPLN metagraph) for every stored atom whose head is the target head.
(= (ContextEvidencePacketsFromKB $space $target-head $prior $cap)
   (collapse
      (match $space (: $proof ($target-head $entity) (STV $s $c))
         (let (EC $pos $neg) (STVToEC (STV $s $c) $prior $cap)
            (if (<= (+ $pos $neg) 0.0)
               (empty)
               (EvidencePacket
                  ($target-head $entity)
                  (EC $pos $neg)
                  (KBEntityFeatures $space $entity $target-head)
                  $proof))))))

; Run the existing scorer/selector/projector over KB-derived packets and features.
(= (GeneratedContextForKBStatement $space $statement $target-head $prior $cap)
   (GeneratedContextForQuery
      $statement
      (ContextEvidencePacketsFromKB $space $target-head $prior $cap)
      (KBStatementFeatures $space $statement $target-head)))

(= (GeneratedContextExplanationForKBStatement $space $statement $target-head $prior $cap)
   (GeneratedContextExplanationForQuery
      $statement
      (ContextEvidencePacketsFromKB $space $target-head $prior $cap)
      (KBStatementFeatures $space $statement $target-head)))

; Default prior/cap convenience wrapper (matches the contextual_query defaults).
(= (GeneratedContextPeTTaChainerResultForKBStatement $space $statement $target-head)
   (ContextExplanationToPeTTaChainerResult
      (GeneratedContextExplanationForKBStatement $space $statement $target-head 2.0 1000.0)))

; Section 8.2 projection under a generated context: project a unary query atom
; (: prf (Head entity) tv) through the selected context guard. Returns
; (: (generated-context) statement (STV s c)), or (empty) when there is no evidence.
(= (ContextProjectionAtomForQuery $space (: $_prf ($head $entity) $_tv) $prior $cap)
   (let $packets (ContextEvidencePacketsFromKB $space $head $prior $cap)
      (if (== $packets ())
         (empty)
         (let (GeneratedContext $_st $_g $_side $_ev $projection $_score)
            (GeneratedContextForQuery ($head $entity) $packets
               (KBStatementFeatures $space ($head $entity) $head))
            (: (generated-context) ($head $entity) $projection)))))

; --- Section 13.2 (weakest adequate chart), ranking view: keep the best and
;     runner-up guards so a sweep can report a ranking margin = best - runner.
;     Strict > matches BestGeneratedContextGuard.
(= (ContextRankInsert
      (RankedPair (ScoredGuard $best-g $best-s) (ScoredGuard $run-g $run-s))
      (ScoredGuard $g $s))
   (if (> $s $best-s)
      (RankedPair (ScoredGuard $g $s) (ScoredGuard $best-g $best-s))
      (if (> $s $run-s)
         (RankedPair (ScoredGuard $best-g $best-s) (ScoredGuard $g $s))
         (RankedPair (ScoredGuard $best-g $best-s) (ScoredGuard $run-g $run-s)))))

(= (ContextRankStep $packets $query-features $ranked $guard)
   (ContextRankInsert
      $ranked
      (ScoredGuard $guard (GeneratedContextScore $guard $packets $query-features))))

(= (GeneratedContextTop2Guards $packets $query-features)
   (fold-flat
      (ContextRankStep $packets $query-features)
      (RankedPair (ScoredGuard none -9999.0) (ScoredGuard none -9999.0))
      (GeneratedContextGuards $packets)))

(= (RankedPairBest (RankedPair (ScoredGuard $g $s) $_runner)) (ScoredGuard $g $s))
(= (RankedPairRunner (RankedPair $_best (ScoredGuard $g $s))) (ScoredGuard $g $s))
(= (RankedPairMargin (RankedPair (ScoredGuard $_bg $bs) (ScoredGuard $_rg $rs))) (- $bs $rs))
