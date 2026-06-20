; PeTTa-native context generation over evidence packets.
;
; The operational core of piPLN section 13.2 (the weakest adequate chart) and
; section 5.2 (weakness as generalized Occam). A packet stores a target
; statement, evidence counts (EC pos neg), and features. A generated context is a
; guard whose inside/outside split lowers the paraconsistent conflict
; 2*min(pos,neg)/total (sections 4.3, 16.1) for the current query. Guards are
; enumerated atomic / pairwise / depth-3 (the candidate charts), scored by
; conflict reduction plus a query-focus bonus minus a depth-graded feature
; penalty (the Fit (x) Weak (x) Rel (x) Cost^-1 score of section 13.2, with the
; feature penalty as the section 13.3 description-length term), and the best is
; selected and projected to a PLN STV by ContextECToSTV (section 8.2). Evidence
; combines by componentwise count addition, the section 8.1 evidence-count
; quantale tensor.

!(import! &self chainer/compile)

(= (ContextBetween $x $lo $hi) (and (> $x $lo) (< $x $hi)))

(= (ContextPacketFeatures (EvidencePacket $_statement $_evidence $features $_provenance)) $features)
(= (ContextAddGuard $guards $guard)
   (if (is-member $guard $guards) $guards (cons $guard $guards)))

(= (ContextAddFeature $features $feature)
   (ContextAddGuard $features $feature))

(= (ContextFeatureUnionStep $features $packet)
   (fold-flat ContextAddFeature $features (ContextPacketFeatures $packet)))

(= (ContextAddPairGuard $left $guards $right)
   (if (= $left $right)
      $guards
      (ContextAddGuard $guards (ContextAnd $left $right))))

(= (ContextPacketPairGuards ()) ())
(= (ContextPacketPairGuards (cons $head $tail))
   (fold-flat (ContextAddPairGuard $head) (ContextPacketPairGuards $tail) $tail))

(= (ContextPairGuardUnionStep $guards $packet)
   (fold-flat ContextAddGuard $guards (ContextPacketPairGuards (ContextPacketFeatures $packet))))

(= (ContextAddTripleGuard $left $guards $pair)
   (ContextAddGuard $guards (ContextAnd $left $pair)))

(= (ContextPacketTripleGuards ()) ())
(= (ContextPacketTripleGuards (cons $head $tail))
   (fold-flat
      (ContextAddTripleGuard $head)
      (ContextPacketTripleGuards $tail)
      (ContextPacketPairGuards $tail)))

(= (ContextTripleGuardUnionStep $guards $packet)
   (fold-flat ContextAddGuard $guards (ContextPacketTripleGuards (ContextPacketFeatures $packet))))

; Section 13.2 candidate charts: enumerate guards atomic, pairwise (ContextAnd),
; and depth-3 from the packet features. The pure enumerator tops out at depth 3;
; the beam (context_generation_beam*.metta) reaches deeper.
(= (GeneratedContextGuards $packets)
   (fold-flat
      ContextTripleGuardUnionStep
      (fold-flat
         ContextPairGuardUnionStep
         (fold-flat ContextFeatureUnionStep () $packets)
         $packets)
      $packets))

(= (ContextGuardMatches $guard $features)
   (if (= $guard (ContextAnd $left $right))
      (and (ContextGuardMatches $left $features) (ContextGuardMatches $right $features))
      (is-member $guard $features)))

(= (ContextSplitAccStep $guard (SplitCounts $in-pos $in-neg $out-pos $out-neg)
      (EvidencePacket $_statement (EC $pos $neg) $features $_provenance))
   (if (ContextGuardMatches $guard $features)
      (SplitCounts (+ $in-pos $pos) (+ $in-neg $neg) $out-pos $out-neg)
      (SplitCounts $in-pos $in-neg (+ $out-pos $pos) (+ $out-neg $neg))))

(= (GeneratedContextSplitCounts $guard $packets)
   (fold-flat (ContextSplitAccStep $guard) (SplitCounts 0.0 0.0 0.0 0.0) $packets))

; Sections 4.3 / 16.1: paraconsistent conflict (dissonance) of an evidence pair,
; 2*min(pos,neg)/total. 0 when one-sided, 1 when perfectly balanced. A good split
; reduces it.
(= (ContextConflict (EC $pos $neg))
   (let $total (+ $pos $neg)
      (if (<= $total 0.0) 0.0 (/ (* 2.0 (min $pos $neg)) $total))))

(= (ContextWeightedSplitConflict (SplitCounts $in-pos $in-neg $out-pos $out-neg))
   (let* (($in-total (+ $in-pos $in-neg))
          ($out-total (+ $out-pos $out-neg))
          ($total (+ $in-total $out-total)))
      (if (<= $total 0.0)
         0.0
         (/ (+ (* (ContextConflict (EC $in-pos $in-neg)) $in-total)
               (* (ContextConflict (EC $out-pos $out-neg)) $out-total))
            $total))))

; Section 8.1 evidence-count quantale tensor: combine packets by componentwise
; count addition (provenance-disjoint composition).
(= (ContextAllEvidenceStep (EC $acc-pos $acc-neg)
      (EvidencePacket $_statement (EC $pos $neg) $_features $_provenance))
   (EC (+ $acc-pos $pos) (+ $acc-neg $neg)))

(= (ContextAllEvidence $packets)
   (fold-flat ContextAllEvidenceStep (EC 0.0 0.0) $packets))

(= (ContextFocusBonus $guard $query-features)
   (if (ContextGuardMatches $guard $query-features)
      (if (= $guard (ContextAnd $_left $_right)) 0.75 0.8)
      0.0))

; Section 13.3: the description-length / MDL term. Deeper conjunctions cost more,
; so a simpler adequate guard wins (the weakness / Occam bias).
(= (ContextFeaturePenalty $guard)
   (if (= $guard none) 0.0
      (if (= $guard (ContextAnd $_first (ContextAnd $_second (ContextAnd $_third $_fourth)))) 0.18
         (if (= $guard (ContextAnd $_left (ContextAnd $_mid $_right))) 0.14
            (if (= $guard (ContextAnd $_left $_right)) 0.10
               (if (= $guard (type $_type)) 0.02
                  (if (= $guard (habitat $_habitat)) 0.03 0.05)))))))

(= (ContextSingleSidedScore $guard $query-features $in-total $out-total)
   (if (ContextGuardMatches $guard $query-features)
      (if (> $in-total 0.0)
         (- (ContextFocusBonus $guard $query-features)
            (ContextFeaturePenalty $guard))
         -9999.0)
      (if (> $out-total 0.0)
         (- 0.0 (ContextFeaturePenalty $guard))
         -9999.0)))

; Section 13.2 chart score = conflict reduction (parent conflict - weighted split
; conflict) + focus bonus - feature penalty. A degenerate one-sided split falls
; back to ContextSingleSidedScore.
(= (GeneratedContextScore $guard $packets $query-features)
   (let* (((EC $parent-pos $parent-neg) (ContextAllEvidence $packets))
          ((SplitCounts $in-pos $in-neg $out-pos $out-neg)
             (GeneratedContextSplitCounts $guard $packets))
          ($in-total (+ $in-pos $in-neg))
          ($out-total (+ $out-pos $out-neg)))
      (if (or (<= $in-total 0.0) (<= $out-total 0.0))
         (ContextSingleSidedScore $guard $query-features $in-total $out-total)
         (+ (- (ContextConflict (EC $parent-pos $parent-neg))
               (ContextWeightedSplitConflict
                  (SplitCounts $in-pos $in-neg $out-pos $out-neg)))
            (- (ContextFocusBonus $guard $query-features)
               (ContextFeaturePenalty $guard))))))

(= (GeneratedContextScoreTrace $guard $packets $query-features)
   (let* (((EC $parent-pos $parent-neg) (ContextAllEvidence $packets))
          ((SplitCounts $in-pos $in-neg $out-pos $out-neg)
             (GeneratedContextSplitCounts $guard $packets))
          ($parent-conflict (ContextConflict (EC $parent-pos $parent-neg)))
          ($split-conflict
             (ContextWeightedSplitConflict
                (SplitCounts $in-pos $in-neg $out-pos $out-neg)))
          ($reduction (- $parent-conflict $split-conflict))
          ($focus (ContextFocusBonus $guard $query-features))
          ($penalty (ContextFeaturePenalty $guard))
          ($score (GeneratedContextScore $guard $packets $query-features)))
      (ContextScoreTrace
         $guard
         (ParentEvidence (EC $parent-pos $parent-neg))
         (SplitCounts $in-pos $in-neg $out-pos $out-neg)
         (ParentConflict $parent-conflict)
         (SplitConflict $split-conflict)
         (ConflictReduction $reduction)
         (FocusBonus $focus)
         (Penalty $penalty)
         (Score $score))))

(= (ContextTraceScore
      (ContextScoreTrace
         $_guard
         $_parent
         $_split
         $_parent-conflict
         $_split-conflict
         $_reduction
         $_focus
         $_penalty
         (Score $score)))
   $score)

(= (ContextGuardAtoms none) ())
(= (ContextGuardAtoms (ContextAnd $first (ContextAnd $second (ContextAnd $third $fourth))))
   ($first $second $third $fourth))
(= (ContextGuardAtoms (ContextAnd $left (ContextAnd $mid (type $type)))) ($left $mid (type $type)))
(= (ContextGuardAtoms (ContextAnd $left (ContextAnd $mid (weather $weather)))) ($left $mid (weather $weather)))
(= (ContextGuardAtoms (ContextAnd $left (ContextAnd $mid (payload $payload)))) ($left $mid (payload $payload)))
(= (ContextGuardAtoms (ContextAnd $left (ContextAnd $mid (habitat $habitat)))) ($left $mid (habitat $habitat)))
(= (ContextGuardAtoms (ContextAnd $left (ContextAnd $mid (source $source)))) ($left $mid (source $source)))
(= (ContextGuardAtoms (ContextAnd $left (type $type))) ($left (type $type)))
(= (ContextGuardAtoms (ContextAnd $left (weather $weather))) ($left (weather $weather)))
(= (ContextGuardAtoms (ContextAnd $left (payload $payload))) ($left (payload $payload)))
(= (ContextGuardAtoms (ContextAnd $left (habitat $habitat))) ($left (habitat $habitat)))
(= (ContextGuardAtoms (ContextAnd $left (source $source))) ($left (source $source)))
(= (ContextGuardAtoms (type $type)) ((type $type)))
(= (ContextGuardAtoms (weather $weather)) ((weather $weather)))
(= (ContextGuardAtoms (payload $payload)) ((payload $payload)))
(= (ContextGuardAtoms (habitat $habitat)) ((habitat $habitat)))
(= (ContextGuardAtoms (source $source)) ((source $source)))

(= (ContextRemoveFeature $_feature ()) ())
(= (ContextRemoveFeature $feature (cons $head $tail))
   (if (== $feature $head)
      (ContextRemoveFeature $feature $tail)
      (cons $head (ContextRemoveFeature $feature $tail))))

(= (ContextGuardFromAtoms ()) none)
(= (ContextGuardFromAtoms (cons $head ())) $head)
(= (ContextGuardFromAtoms (cons $left (cons $right ()))) (ContextAnd $left $right))
(= (ContextGuardFromAtoms (cons $left (cons $mid (cons $right ()))))
   (ContextAnd $left (ContextAnd $mid $right)))
(= (ContextGuardFromAtoms (cons $first (cons $second (cons $third (cons $fourth ())))))
   (ContextAnd $first (ContextAnd $second (ContextAnd $third $fourth))))

(= (ContextAblationReducedGuard $guard $feature)
   (ContextGuardFromAtoms (ContextRemoveFeature $feature (ContextGuardAtoms $guard))))

(= (ContextAblationForFeature $guard $packets $query-features $feature)
   (let* (($reduced (ContextAblationReducedGuard $guard $feature))
          ($full-trace (GeneratedContextScoreTrace $guard $packets $query-features))
          ($reduced-trace (GeneratedContextScoreTrace $reduced $packets $query-features))
          ($delta (- (ContextTraceScore $full-trace) (ContextTraceScore $reduced-trace))))
      (ContextAblation
         (RemovedFeature $feature)
         (ReducedGuard $reduced)
         $reduced-trace
         (ScoreDelta $delta))))

(= (ContextAblationStep $guard $packets $query-features $reports $feature)
   (cons (ContextAblationForFeature $guard $packets $query-features $feature) $reports))

(= (BuildContextMinimalityReport $guard $packets $query-features)
   (ContextMinimalityReport
      (FullTrace (GeneratedContextScoreTrace $guard $packets $query-features))
      (Ablations
         (fold-flat
            (ContextAblationStep $guard $packets $query-features)
            ()
            (ContextGuardAtoms $guard)))))

(= (ContextAblationDelta
      (ContextAblation $_removed $_reduced $_trace (ScoreDelta $delta)))
   $delta)

(= (ContextAblationReduced
      (ContextAblation $_removed (ReducedGuard $reduced) $_trace $_delta))
   $reduced)

(= (ContextBetterScoredGuard
      $packets
      $query-features
      (ScoredGuard $best-guard $best-score)
      $guard)
   (let $score (GeneratedContextScore $guard $packets $query-features)
      (if (> $score $best-score)
         (ScoredGuard $guard $score)
         (ScoredGuard $best-guard $best-score))))

(= (BestGeneratedContextGuard $packets $query-features)
   (fold-flat
      (ContextBetterScoredGuard $packets $query-features)
      (ScoredGuard none -9999.0)
      (GeneratedContextGuards $packets)))

(= (GeneratedContextEvidence $guard $query-features $packets)
   (let (SplitCounts $in-pos $in-neg $out-pos $out-neg)
      (GeneratedContextSplitCounts $guard $packets)
      (if (ContextGuardMatches $guard $query-features)
         (SelectedEvidence inside (EC $in-pos $in-neg))
         (SelectedEvidence outside (EC $out-pos $out-neg)))))

(= (ContextSupportStep $guard $query-features $support
      (EvidencePacket $statement $evidence $features $provenance))
   (let* (($query-inside (ContextGuardMatches $guard $query-features))
          ($packet-inside (ContextGuardMatches $guard $features)))
      (if (= $query-inside $packet-inside)
         (cons (SupportPacket $statement $evidence $features $provenance) $support)
         $support)))

(= (GeneratedContextSupport $guard $query-features $packets)
   (fold-flat (ContextSupportStep $guard $query-features) () $packets))

(= (ContextEvidencePacketsFromSpace $space $predicate)
   (collapse
      (match $space
         (ContextEvidence $predicate $statement $evidence $features $provenance)
         (EvidencePacket $statement $evidence $features $provenance))))

(= (ContextFeatureUnionListStep $features $packet-features)
   (fold-flat ContextAddFeature $features $packet-features))

(= (ContextQueryFeaturesFromSpace $space $predicate $statement)
   (fold-flat
      ContextFeatureUnionListStep
      (fold-flat
         ContextFeatureUnionListStep
         ()
         (collapse
            (match $space
               (ContextEvidence $predicate $statement $_evidence $features $_provenance)
               $features)))
      (collapse
         (match $space
            (ContextStatementFeatures $predicate $statement $features)
            $features))))

(= (ContextECToSTV (EC $pos $neg) $p0 $k)
   (let* (($n (+ $pos $neg))
          ($den (+ $n $k))
          ($s (if (<= $den 0.0) $p0 (/ (+ $pos (* $k $p0)) $den)))
          ($c (if (<= $den 0.0) 0.0 (/ $n $den))))
      (STV $s $c)))

(= (GeneratedContextForQuery $statement $packets $query-features)
   (let* (((ScoredGuard $guard $score) (BestGeneratedContextGuard $packets $query-features))
          ((SelectedEvidence $side $evidence)
             (GeneratedContextEvidence $guard $query-features $packets))
          ($projection (ContextECToSTV $evidence 0.95 2.0)))
      (GeneratedContext $statement $guard $side $evidence $projection $score)))

(= (GeneratedContextExplanationForQuery $statement $packets $query-features)
   (let* (((GeneratedContext $_statement $guard $side $evidence $projection $_score)
             (GeneratedContextForQuery $statement $packets $query-features))
          ($support (GeneratedContextSupport $guard $query-features $packets))
          ($trace (GeneratedContextScoreTrace $guard $packets $query-features)))
      (ContextExplanation $statement $guard $side $evidence $projection $support $trace)))

(= (GeneratedContextMinimalityReportForQuery $statement $packets $query-features)
   (let (GeneratedContext $_statement $guard $_side $_evidence $_projection $_score)
      (GeneratedContextForQuery $statement $packets $query-features)
      (BuildContextMinimalityReport $guard $packets $query-features)))

(= (ContextExplanationToChainingTriple
      (ContextExplanation $statement $guard $side $evidence $projection $support $trace))
   (: $projection
      (context-answer
         (collect-evidence $support)
         (generate-context $guard)
         (score-context $trace)
         (select-evidence $side $evidence)
         (project-evidence $projection))
      $statement))

(= (GeneratedContextChainingTripleForQuery $statement $packets $query-features)
   (ContextExplanationToChainingTriple
      (GeneratedContextExplanationForQuery $statement $packets $query-features)))

; PeTTaChainer query results are proof-first: (: proof statement truth-value).
(= (ContextExplanationToPeTTaChainerResult
      (ContextExplanation $statement $guard $side $evidence $projection $support $trace))
   (: (context-generated-proof
         (collect-evidence $support)
         (generate-context $guard)
         (score-context $trace)
         (select-evidence $side $evidence)
         (project-evidence $projection))
      $statement
      $projection))

(= (GeneratedContextPeTTaChainerResultForQuery $statement $packets $query-features)
   (ContextExplanationToPeTTaChainerResult
      (GeneratedContextExplanationForQuery $statement $packets $query-features)))

(= (GeneratedContextCertifiedPeTTaChainerResultForQuery $statement $packets $query-features)
   (let* (((ContextExplanation $_statement $guard $side $evidence $projection $support $trace)
             (GeneratedContextExplanationForQuery $statement $packets $query-features))
          ($minimality (BuildContextMinimalityReport $guard $packets $query-features)))
      (: (context-certified-generated-proof
            (collect-evidence $support)
            (generate-context $guard)
            (score-context $trace)
            (certify-minimality $minimality)
            (select-evidence $side $evidence)
            (project-evidence $projection))
         $statement
         $projection)))

(= (ContextTripleProjection (: $projection $_proof $_statement)) $projection)
(= (ContextTripleProof (: $_projection $proof $_statement)) $proof)
(= (ContextTripleStatement (: $_projection $_proof $statement)) $statement)

(= (ContextPeTTaChainerResultProof (: $proof $_statement $_projection)) $proof)
(= (ContextPeTTaChainerResultStatement (: $_proof $statement $_projection)) $statement)
(= (ContextPeTTaChainerResultProjection (: $_proof $_statement $projection)) $projection)

(= (ContextProofGuard
      (context-answer
         $_collect
         (generate-context $guard)
         $_score
         $_select
         $_project))
   $guard)

(= (ContextPeTTaChainerProofGuard
      (context-generated-proof
         $_collect
         (generate-context $guard)
         $_score
         $_select
         $_project))
   $guard)

(= (ContextCertifiedPeTTaChainerProofGuard
      (context-certified-generated-proof
         $_collect
         (generate-context $guard)
         $_score
         $_minimality
         $_select
         $_project))
   $guard)

(= (ContextCertifiedPeTTaChainerProofMinimality
      (context-certified-generated-proof
         $_collect
         $_generate
         $_score
         (certify-minimality $minimality)
         $_select
         $_project))
   $minimality)

(= (GeneratedContextForSpaceQuery $space $predicate $statement $query-features)
   (GeneratedContextForQuery
      $statement
      (ContextEvidencePacketsFromSpace $space $predicate)
      $query-features))

(= (GeneratedContextForSpaceStatement $space $predicate $statement)
   (GeneratedContextForSpaceQuery
      $space
      $predicate
      $statement
      (ContextQueryFeaturesFromSpace $space $predicate $statement)))

(= (GeneratedContextExplanationForSpaceQuery $space $predicate $statement $query-features)
   (GeneratedContextExplanationForQuery
      $statement
      (ContextEvidencePacketsFromSpace $space $predicate)
      $query-features))

(= (GeneratedContextMinimalityReportForSpaceQuery $space $predicate $statement $query-features)
   (GeneratedContextMinimalityReportForQuery
      $statement
      (ContextEvidencePacketsFromSpace $space $predicate)
      $query-features))

(= (GeneratedContextExplanationForSpaceStatement $space $predicate $statement)
   (GeneratedContextExplanationForSpaceQuery
      $space
      $predicate
      $statement
      (ContextQueryFeaturesFromSpace $space $predicate $statement)))

(= (GeneratedContextMinimalityReportForSpaceStatement $space $predicate $statement)
   (GeneratedContextMinimalityReportForSpaceQuery
      $space
      $predicate
      $statement
      (ContextQueryFeaturesFromSpace $space $predicate $statement)))

(= (GeneratedContextChainingTripleForSpaceQuery $space $predicate $statement $query-features)
   (ContextExplanationToChainingTriple
      (GeneratedContextExplanationForSpaceQuery $space $predicate $statement $query-features)))

(= (GeneratedContextChainingTripleForSpaceStatement $space $predicate $statement)
   (ContextExplanationToChainingTriple
      (GeneratedContextExplanationForSpaceStatement $space $predicate $statement)))

(= (GeneratedContextPeTTaChainerResultForSpaceQuery $space $predicate $statement $query-features)
   (ContextExplanationToPeTTaChainerResult
      (GeneratedContextExplanationForSpaceQuery $space $predicate $statement $query-features)))

(= (GeneratedContextCertifiedPeTTaChainerResultForSpaceQuery $space $predicate $statement $query-features)
   (GeneratedContextCertifiedPeTTaChainerResultForQuery
      $statement
      (ContextEvidencePacketsFromSpace $space $predicate)
      $query-features))

(= (GeneratedContextPeTTaChainerResultForSpaceStatement $space $predicate $statement)
   (ContextExplanationToPeTTaChainerResult
      (GeneratedContextExplanationForSpaceStatement $space $predicate $statement)))

(= (GeneratedContextCertifiedPeTTaChainerResultForSpaceStatement $space $predicate $statement)
   (GeneratedContextCertifiedPeTTaChainerResultForSpaceQuery
      $space
      $predicate
      $statement
      (ContextQueryFeaturesFromSpace $space $predicate $statement)))
