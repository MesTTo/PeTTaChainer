; Prolog-backed beam scorer for generated contexts.
;
; Same section 13.2 search as the pure beam, but reaches deeper than the depth-3
; enumerator. It returns ranked candidate charts plus a section 5.2 minimality
; (Occam) certificate built by ablation (BuildContextMinimalityReport).
;
; This follows PeTTa's examples/prologimport.metta: the expensive
; candidate enumeration and scoring runs in Prolog, while the result is exposed
; as a normal PeTTa function returning MeTTa atoms. Interop pattern:
; import_prolog_functions_from_file.

!(import! &self context/context_generation)
!(import! &self (library lib_import))
!(import_prolog_functions_from_file "./context/context_generation_beam.pl" (context_beam_for_query))

(= (ContextBeamForSpaceQuery $space $predicate $statement $query-features $max-depth $beam-width)
   (context_beam_for_query
      $statement
      (ContextEvidencePacketsFromSpace $space $predicate)
      $query-features
      $max-depth
      $beam-width))

(= (ContextBeamForSpaceStatement $space $predicate $statement $max-depth $beam-width)
   (ContextBeamForSpaceQuery
      $space
      $predicate
      $statement
      (ContextQueryFeaturesFromSpace $space $predicate $statement)
      $max-depth
      $beam-width))

(= (ContextBeamAnswerToChainingTriple
      (ContextBeamAnswer $statement $guard $side $evidence $projection $support $trace $beam))
   (: $projection
      (context-beam-answer
         (collect-evidence $support)
         (generate-context $guard)
         (score-context $trace)
         (select-evidence $side $evidence)
         (project-evidence $projection)
         $beam)
      $statement))

(= (ContextBeamAnswerToPeTTaChainerResult
      (ContextBeamAnswer $statement $guard $side $evidence $projection $support $trace $beam))
   (: (context-beam-generated-proof
         (collect-evidence $support)
         (generate-context $guard)
         (score-context $trace)
         (select-evidence $side $evidence)
         (project-evidence $projection)
         $beam)
      $statement
      $projection))

; Attaches the section 5.2 minimality (Occam) certificate: ablate each guard
; feature and rescore, so the kept chart is shown to be no stronger than needed.
(= (ContextBeamAnswerToCertifiedPeTTaChainerResult
      $packets
      $query-features
      (ContextBeamAnswer $statement $guard $side $evidence $projection $support $trace $beam))
   (: (context-certified-beam-generated-proof
         (collect-evidence $support)
         (generate-context $guard)
         (score-context $trace)
         (certify-minimality (BuildContextMinimalityReport $guard $packets $query-features))
         (select-evidence $side $evidence)
         (project-evidence $projection)
         $beam)
      $statement
      $projection))

(= (ContextBeamChainingTripleForQuery $statement $packets $query-features $max-depth $beam-width)
   (ContextBeamAnswerToChainingTriple
      (context_beam_for_query
         $statement
         $packets
         $query-features
         $max-depth
         $beam-width)))

(= (ContextBeamPeTTaChainerResultForQuery $statement $packets $query-features $max-depth $beam-width)
   (ContextBeamAnswerToPeTTaChainerResult
      (context_beam_for_query
         $statement
         $packets
         $query-features
         $max-depth
         $beam-width)))

(= (ContextBeamCertifiedPeTTaChainerResultForQuery $statement $packets $query-features $max-depth $beam-width)
   (ContextBeamAnswerToCertifiedPeTTaChainerResult
      $packets
      $query-features
      (context_beam_for_query
         $statement
         $packets
         $query-features
         $max-depth
         $beam-width)))

(= (ContextBeamChainingTripleForSpaceQuery
      $space
      $predicate
      $statement
      $query-features
      $max-depth
      $beam-width)
   (ContextBeamAnswerToChainingTriple
      (ContextBeamForSpaceQuery
         $space
         $predicate
         $statement
         $query-features
         $max-depth
         $beam-width)))

(= (ContextBeamChainingTripleForSpaceStatement $space $predicate $statement $max-depth $beam-width)
   (ContextBeamAnswerToChainingTriple
      (ContextBeamForSpaceStatement
         $space
         $predicate
         $statement
         $max-depth
         $beam-width)))

(= (ContextBeamPeTTaChainerResultForSpaceQuery
      $space
      $predicate
      $statement
      $query-features
      $max-depth
      $beam-width)
   (ContextBeamAnswerToPeTTaChainerResult
      (ContextBeamForSpaceQuery
         $space
         $predicate
         $statement
         $query-features
         $max-depth
         $beam-width)))

(= (ContextBeamCertifiedPeTTaChainerResultForSpaceQuery
      $space
      $predicate
      $statement
      $query-features
      $max-depth
      $beam-width)
   (ContextBeamCertifiedPeTTaChainerResultForQuery
      $statement
      (ContextEvidencePacketsFromSpace $space $predicate)
      $query-features
      $max-depth
      $beam-width))

(= (ContextBeamPeTTaChainerResultForSpaceStatement $space $predicate $statement $max-depth $beam-width)
   (ContextBeamAnswerToPeTTaChainerResult
      (ContextBeamForSpaceStatement
         $space
         $predicate
         $statement
         $max-depth
         $beam-width)))

(= (ContextBeamCertifiedPeTTaChainerResultForSpaceStatement $space $predicate $statement $max-depth $beam-width)
   (ContextBeamCertifiedPeTTaChainerResultForSpaceQuery
      $space
      $predicate
      $statement
      (ContextQueryFeaturesFromSpace $space $predicate $statement)
      $max-depth
      $beam-width))

(= (ContextBeamProofGuard
      (context-beam-answer
         $_collect
         (generate-context $guard)
         $_score
         $_select
         $_project
         $_beam))
   $guard)

(= (ContextBeamCertifiedPeTTaChainerProofGuard
      (context-certified-beam-generated-proof
         $_collect
         (generate-context $guard)
         $_score
         $_minimality
         $_select
         $_project
         $_beam))
   $guard)

(= (ContextBeamCertifiedPeTTaChainerProofMinimality
      (context-certified-beam-generated-proof
         $_collect
         $_generate
         $_score
         (certify-minimality $minimality)
         $_select
         $_project
         $_beam))
   $minimality)

(= (ContextBeamCertifiedPeTTaChainerProofBeam
      (context-certified-beam-generated-proof
         $_collect
         $_generate
         $_score
         $_minimality
         $_select
         $_project
         $beam))
   $beam)

(= (ContextBeamPeTTaChainerProofGuard
      (context-beam-generated-proof
         $_collect
         (generate-context $guard)
         $_score
         $_select
         $_project
         $_beam))
   $guard)
