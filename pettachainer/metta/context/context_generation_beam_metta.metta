; Pure-MeTTa beam scorer for generated contexts.
;
; Realizes section 13.2 (the weakest adequate chart) by beam search instead of
; the greedy depth-3 enumerator. It enumerates depth-k guards by combinatorics
; (chooseKl), scores each with the shared GeneratedContextScore (section 13.2),
; keeps the top beam-width, and projects via ContextECToSTV (section 8.2).
;
; This is a drop-in alternative to the Prolog beam in context_generation_beam.pl.
; It enumerates candidate guards up to arity max-depth, scores each one with the
; existing GeneratedContextScore from context_generation.metta, keeps the top
; beam-width by score, picks the best, and returns the same ContextBeamAnswer
; shape the Prolog context_beam_for_query/6 returns. Because the scoring,
; evidence selection, support collection, and projection all reuse the heads in
; context_generation.metta, the two beams agree field-by-field on the selected
; guard, the route, the projection, the support packets, and the trace.
;
; The enumeration uses chooseKl from lib_combinatorics: (chooseKl List K) returns
; a list of the K-subsets of List, each subset a cons-list in the same
; left-to-right order as the input. ContextGuardFromAtoms turns a subset like
; (cons f1 (cons f2 (cons f3 ()))) into (ContextAnd f1 (ContextAnd f2 f3)),
; which is exactly the nesting guard_from_features/2 builds in Prolog. To match
; the Prolog first-seen feature order we reverse the front-cons feature union.

!(import! &self context/context_generation)
!(import! &self (library lib_combinatorics))

; ----- small cons-list utilities (named to avoid clashing with builtins) -----

; Reverse a cons-list. Named ContextBeamReverse because `reverse` is a static
; Prolog predicate and cannot be redefined.
(= (ContextBeamReverseStep $acc $x) (cons $x $acc))
(= (ContextBeamReverse $xs) (fold-flat ContextBeamReverseStep () $xs))

; The integers $k..$max as a cons-list, for folding over candidate arities.
(= (ContextBeamDepthList $k $max)
   (if (> $k $max) () (cons $k (ContextBeamDepthList (+ $k 1) $max))))

; Take the first $n items of a cons-list. One head with a single decision keeps
; this deterministic: overlapping base clauses (0 vs empty) would otherwise make
; MeTTa return the result twice.
(= (ContextBeamTake $n $reports)
   (if (or (< $n 1) (== $reports ()))
      ()
      (cons (car-atom $reports)
            (ContextBeamTake (- $n 1) (cdr-atom $reports)))))

; ----- candidate guard enumeration -----

; Union of all packet features as a cons-list, in first-seen order. The existing
; ContextFeatureUnionStep folds with a front cons (so it dedups but reverses), so
; we reverse once to recover the order Prolog's all_features/2 preserves.
(= (ContextBeamFeatureUnion $packets)
   (ContextBeamReverse (fold-flat ContextFeatureUnionStep () $packets)))

; Append the arity-$k guards (one per k-subset) onto the accumulator.
(= (ContextBeamGuardsAtDepthStep $features $guards $k)
   (append
      (map-atom (chooseKl $features $k)
                (|-> ($subset) (ContextGuardFromAtoms $subset)))
      $guards))

; All candidate guards from arity 1 up to $max-depth. The candidate charts the
; section 13.2 weakness score ranks over.
(= (ContextBeamCandidateGuards $packets $max-depth)
   (let $features (ContextBeamFeatureUnion $packets)
      (fold-flat
         (ContextBeamGuardsAtDepthStep $features)
         ()
         (ContextBeamDepthList 1 $max-depth))))

; ----- scored candidate records -----

; One scored record per guard: (ScoredReport score guard trace). Score and trace
; come straight from the pure-MeTTa heads, so the numbers match the Prolog beam.
(= (ContextBeamScoredReport $packets $query-features $guard)
   (ScoredReport
      (GeneratedContextScore $guard $packets $query-features)
      $guard
      (GeneratedContextScoreTrace $guard $packets $query-features)))

(= (ContextBeamScoredReportStep $packets $query-features $reports $guard)
   (cons (ContextBeamScoredReport $packets $query-features $guard) $reports))

(= (ContextBeamScoredReports $packets $query-features $guards)
   (fold-flat
      (ContextBeamScoredReportStep $packets $query-features)
      ()
      $guards))

(= (ContextBeamReportScore (ScoredReport $score $_guard $_trace)) $score)

; ----- sort scored records by score, descending -----

(= (ContextBeamInsert $report ()) (cons $report ()))
(= (ContextBeamInsert $report (cons $head $tail))
   (if (> (ContextBeamReportScore $report) (ContextBeamReportScore $head))
      (cons $report (cons $head $tail))
      (cons $head (ContextBeamInsert $report $tail))))

(= (ContextBeamSortStep $sorted $report) (ContextBeamInsert $report $sorted))

(= (ContextBeamSortReports $reports)
   (fold-flat ContextBeamSortStep () $reports))

; ----- beam entries in the Prolog (CandidateReport Guard Trace) shape -----

(= (ContextBeamCandidateEntry (ScoredReport $_score $guard $trace))
   (CandidateReport $guard $trace))
(= (ContextBeamEntriesStep $entries $scored)
   (cons (ContextBeamCandidateEntry $scored) $entries))
(= (ContextBeamCandidateEntries $scored-reports)
   (ContextBeamReverse (fold-flat ContextBeamEntriesStep () $scored-reports)))

; ----- top-level beam -----

; The section 13.2 beam selection: keep the top beam-width charts by weakness
; score, take the best, then project the winner with ContextECToSTV (section 8.2).
; ContextBeamForQueryMeTTa builds the same ContextBeamAnswer the Prolog
; context_beam_for_query/6 returns:
;   (ContextBeamAnswer Statement Guard Side Evidence Projection Support Trace
;                      (Beam Reports))
; with the fallback answer (none / outside / empty) when there is no candidate or
; the beam width is zero, matching the Prolog else-branch exactly.
(= (ContextBeamForQueryMeTTa $statement $packets $query-features $max-depth $beam-width)
   (let* (($guards (ContextBeamCandidateGuards $packets $max-depth))
          ($scored (ContextBeamScoredReports $packets $query-features $guards))
          ($sorted (ContextBeamSortReports $scored))
          ($beam (ContextBeamTake $beam-width $sorted)))
      (if (== $beam ())
         (ContextBeamAnswer
            $statement
            none
            outside
            (EC 0.0 0.0)
            (STV 0.95 0.0)
            ()
            (ContextScoreTrace none)
            (Beam ()))
         (let (ScoredReport $_score $best-guard $best-trace) (car-atom $beam)
            (let (SelectedEvidence $side $evidence)
                 (GeneratedContextEvidence $best-guard $query-features $packets)
               (ContextBeamAnswer
                  $statement
                  $best-guard
                  $side
                  $evidence
                  (ContextECToSTV $evidence 0.95 2.0)
                  (GeneratedContextSupport $best-guard $query-features $packets)
                  $best-trace
                  (Beam (ContextBeamCandidateEntries $beam))))))))

; ----- space- and statement-level wrappers, mirroring the Prolog beam API -----

(= (ContextBeamForQueryMeTTaSpaceQuery $space $predicate $statement $query-features $max-depth $beam-width)
   (ContextBeamForQueryMeTTa
      $statement
      (ContextEvidencePacketsFromSpace $space $predicate)
      $query-features
      $max-depth
      $beam-width))

(= (ContextBeamForQueryMeTTaSpaceStatement $space $predicate $statement $max-depth $beam-width)
   (ContextBeamForQueryMeTTaSpaceQuery
      $space
      $predicate
      $statement
      (ContextQueryFeaturesFromSpace $space $predicate $statement)
      $max-depth
      $beam-width))
