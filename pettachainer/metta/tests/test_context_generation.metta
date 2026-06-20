!(import! &self context/context_generation)

(= (DemoFlyPackets)
   ((EvidencePacket
       (Fly robin)
       (EC 950.0 50.0)
       ((type Bird) (habitat temperate) (source aviary))
       robin-flight)
    (EvidencePacket
       (Fly polly)
       (EC 0.0 100.0)
       ((type Bird) (type Penguin) (source antarctic-study))
       polly-flight)
    (EvidencePacket
       (Fly city-bird)
       (EC 50.0 450.0)
       ((type Bird) (habitat urban) (source urban-survey))
       city-flight)))

(= (DemoQueryFeatures tweety) ((type Bird) (type Penguin) (source zoo-record)))
(= (DemoQueryFeatures city-bird) ((type Bird) (habitat urban) (source camera)))

(= (CompoundFlyPackets)
   ((EvidencePacket
       (Fly micro-calm)
       (EC 300.0 0.0)
       ((type MicroDrone) (weather calm) (source flight-log))
       micro-calm-flight)
    (EvidencePacket
       (Fly heavy-crosswind)
       (EC 300.0 0.0)
       ((type HeavyDrone) (weather crosswind) (source certification))
       heavy-crosswind-flight)
    (EvidencePacket
       (Fly heavy-calm)
       (EC 300.0 0.0)
       ((type HeavyDrone) (weather calm) (source flight-log))
       heavy-calm-flight)
    (EvidencePacket
       (Fly micro-crosswind)
       (EC 0.0 300.0)
       ((type MicroDrone) (weather crosswind) (source incident-report))
       micro-crosswind-incident)))

(= (CompoundQueryFeatures micro-crosswind) ((type MicroDrone) (weather crosswind)))

(= (TripleFlyPackets)
   ((EvidencePacket
       (Fly micro-crosswind-normal)
       (EC 300.0 0.0)
       ((type MicroDrone) (weather crosswind) (payload normal))
       micro-crosswind-normal-flight)
    (EvidencePacket
       (Fly micro-calm-fragile)
       (EC 300.0 0.0)
       ((type MicroDrone) (weather calm) (payload fragile))
       micro-calm-fragile-flight)
    (EvidencePacket
       (Fly heavy-crosswind-fragile)
       (EC 300.0 0.0)
       ((type HeavyDrone) (weather crosswind) (payload fragile))
       heavy-crosswind-fragile-flight)
    (EvidencePacket
       (Fly heavy-calm-normal)
       (EC 300.0 0.0)
       ((type HeavyDrone) (weather calm) (payload normal))
       heavy-calm-normal-flight)
    (EvidencePacket
       (Fly micro-crosswind-fragile)
       (EC 0.0 300.0)
       ((type MicroDrone) (weather crosswind) (payload fragile))
       micro-crosswind-fragile-incident)))

(= (TripleQueryFeatures micro-crosswind-fragile)
   ((type MicroDrone) (weather crosswind) (payload fragile)))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly atom-micro-crosswind-normal)
      (EC 300.0 0.0)
      ((type AtomMicroDrone) (weather atom-crosswind) (payload atom-normal))
      atom-micro-crosswind-normal-flight))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly atom-micro-calm-fragile)
      (EC 300.0 0.0)
      ((type AtomMicroDrone) (weather atom-calm) (payload atom-fragile))
      atom-micro-calm-fragile-flight))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly atom-heavy-crosswind-fragile)
      (EC 300.0 0.0)
      ((type AtomHeavyDrone) (weather atom-crosswind) (payload atom-fragile))
      atom-heavy-crosswind-fragile-flight))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly atom-heavy-calm-normal)
      (EC 300.0 0.0)
      ((type AtomHeavyDrone) (weather atom-calm) (payload atom-normal))
      atom-heavy-calm-normal-flight))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly atom-micro-crosswind-fragile)
      (EC 0.0 300.0)
      ((type AtomMicroDrone) (weather atom-crosswind) (payload atom-fragile))
      atom-micro-crosswind-fragile-incident))

!(add-atom &self
   (ContextStatementFeatures
      Fly
      (Fly atom-unseen-micro-crosswind-fragile)
      ((type AtomMicroDrone) (weather atom-crosswind) (payload atom-fragile))))

(= (AtomspaceQueryFeatures atom-micro-crosswind-fragile)
   ((type AtomMicroDrone) (weather atom-crosswind) (payload atom-fragile)))

!(test
   (let (ScoredGuard $guard $_score)
      (BestGeneratedContextGuard (DemoFlyPackets) (DemoQueryFeatures tweety))
      $guard)
   (type Penguin))

!(test
   (GeneratedContextEvidence
      (type Penguin)
      (DemoQueryFeatures tweety)
      (DemoFlyPackets))
   (SelectedEvidence inside (EC 0.0 100.0)))

!(test
   (let (GeneratedContext
           $_statement
           $guard
           $side
           $evidence
           $_projection
           $_score)
      (GeneratedContextForQuery
         (Fly tweety)
         (DemoFlyPackets)
         (DemoQueryFeatures tweety))
      (GeneratedRoute $guard $side $evidence))
   (GeneratedRoute (type Penguin) inside (EC 0.0 100.0)))

!(test
   (let (GeneratedContext
           $_statement
           $_guard
           $_side
           $_evidence
           (STV $strength $confidence)
           $_score)
      (GeneratedContextForQuery
         (Fly tweety)
         (DemoFlyPackets)
         (DemoQueryFeatures tweety))
      (and
         (ContextBetween $strength 0.018 0.019)
         (ContextBetween $confidence 0.980 0.981)))
   true)

!(test
   (let (GeneratedContext
           $_statement
           $guard
           $side
           $evidence
           $_projection
           $_score)
      (GeneratedContextForQuery
         (Fly city-bird)
         (DemoFlyPackets)
         (DemoQueryFeatures city-bird))
      (GeneratedRoute $guard $side $evidence))
   (GeneratedRoute (habitat urban) inside (EC 50.0 450.0)))

!(test
   (let (ScoredGuard $guard $_score)
      (BestGeneratedContextGuard
         (CompoundFlyPackets)
         (CompoundQueryFeatures micro-crosswind))
      $guard)
   (ContextAnd (type MicroDrone) (weather crosswind)))

!(test
   (let (GeneratedContext
           $_statement
           $guard
           $side
           $evidence
           $_projection
           $_score)
      (GeneratedContextForQuery
         (Fly micro-crosswind)
         (CompoundFlyPackets)
         (CompoundQueryFeatures micro-crosswind))
      (GeneratedRoute $guard $side $evidence))
   (GeneratedRoute
      (ContextAnd (type MicroDrone) (weather crosswind))
      inside
      (EC 0.0 300.0)))

!(test
   (let (ContextExplanation
           $_statement
           $_guard
           $_side
           $_evidence
           $_projection
           $_support
           (ContextScoreTrace
              $_trace-guard
              $_parent
              $_split
              $_parent-conflict
              $_split-conflict
              (ConflictReduction $reduction)
              $_focus
              $_penalty
              (Score $score)))
      (GeneratedContextExplanationForQuery
         (Fly micro-crosswind)
         (CompoundFlyPackets)
         (CompoundQueryFeatures micro-crosswind))
      (and
         (ContextBetween $reduction 0.499 0.501)
         (ContextBetween $score 1.149 1.151)))
   true)

!(test
   (GeneratedContextSupport
      (ContextAnd (type MicroDrone) (weather crosswind))
      (CompoundQueryFeatures micro-crosswind)
      (CompoundFlyPackets))
   ((SupportPacket
       (Fly micro-crosswind)
       (EC 0.0 300.0)
       ((type MicroDrone) (weather crosswind) (source incident-report))
       micro-crosswind-incident)))

!(test
   (let (GeneratedContext
           $_statement
           $_guard
           $_side
           $_evidence
           (STV $strength $confidence)
           $_score)
      (GeneratedContextForQuery
         (Fly micro-crosswind)
         (CompoundFlyPackets)
         (CompoundQueryFeatures micro-crosswind))
      (and
         (ContextBetween $strength 0.006 0.007)
         (ContextBetween $confidence 0.993 0.994)))
   true)

!(test
   (GeneratedContextSplitCounts
      (ContextAnd (type MicroDrone) (weather crosswind))
      (TripleFlyPackets))
   (SplitCounts 300.0 300.0 900.0 0.0))

!(test
   (GeneratedContextSplitCounts
      (ContextAnd (type MicroDrone) (ContextAnd (weather crosswind) (payload fragile)))
      (TripleFlyPackets))
   (SplitCounts 0.0 300.0 1200.0 0.0))

!(test
   (let (ScoredGuard $guard $_score)
      (BestGeneratedContextGuard
         (TripleFlyPackets)
         (TripleQueryFeatures micro-crosswind-fragile))
      $guard)
   (ContextAnd (type MicroDrone) (ContextAnd (weather crosswind) (payload fragile))))

!(test
   (let* (($triple-score
             (GeneratedContextScore
                (ContextAnd (type MicroDrone) (ContextAnd (weather crosswind) (payload fragile)))
                (TripleFlyPackets)
                (TripleQueryFeatures micro-crosswind-fragile)))
          ($single-score
             (GeneratedContextScore
                (type MicroDrone)
                (TripleFlyPackets)
                (TripleQueryFeatures micro-crosswind-fragile)))
          ($pair-score
             (GeneratedContextScore
                (ContextAnd (type MicroDrone) (weather crosswind))
                (TripleFlyPackets)
                (TripleQueryFeatures micro-crosswind-fragile))))
      (and (> $triple-score $single-score) (> $triple-score $pair-score)))
   true)

!(test
   (length
      (ContextGuardAtoms
         (ContextAnd (type MicroDrone) (ContextAnd (weather crosswind) (payload fragile)))))
   3)

!(test
   (let (ContextAblation
           $_removed
           $_reduced
           $_trace
           (ScoreDelta $delta))
      (ContextAblationForFeature
         (ContextAnd (type MicroDrone) (ContextAnd (weather crosswind) (payload fragile)))
         (TripleFlyPackets)
         (TripleQueryFeatures micro-crosswind-fragile)
         (payload fragile))
      (ContextBetween $delta 0.35 0.37))
   true)

!(test
   (let (ContextMinimalityReport
           (FullTrace
              (ContextScoreTrace
                 $_trace-guard
                 $_parent
                 $_split
                 $_parent-conflict
                 $_split-conflict
                 $_reduction
                 $_focus
                 $_penalty
                 (Score $score)))
           (Ablations $ablations))
      (GeneratedContextMinimalityReportForQuery
         (Fly micro-crosswind-fragile)
         (TripleFlyPackets)
         (TripleQueryFeatures micro-crosswind-fragile))
      (and
         (= (length $ablations) 3)
         (ContextBetween $score 1.009 1.011)))
   true)

!(test
   (let (ContextExplanation
           $_statement
           $_guard
           $_side
           $_evidence
           $_projection
           $_support
           (ContextScoreTrace
              $_trace-guard
              $_parent
              $_split
              $_parent-conflict
              $_split-conflict
              (ConflictReduction $reduction)
              $_focus
              $_penalty
              (Score $score)))
      (GeneratedContextExplanationForQuery
         (Fly micro-crosswind-fragile)
         (TripleFlyPackets)
         (TripleQueryFeatures micro-crosswind-fragile))
      (and
         (ContextBetween $reduction 0.399 0.401)
         (ContextBetween $score 1.009 1.011)))
   true)

!(test
   (GeneratedContextSupport
      (ContextAnd (type MicroDrone) (ContextAnd (weather crosswind) (payload fragile)))
      (TripleQueryFeatures micro-crosswind-fragile)
      (TripleFlyPackets))
   ((SupportPacket
       (Fly micro-crosswind-fragile)
       (EC 0.0 300.0)
       ((type MicroDrone) (weather crosswind) (payload fragile))
       micro-crosswind-fragile-incident)))

!(test
   (length (ContextEvidencePacketsFromSpace &self Fly))
   5)

!(test
   (and
      (= (length
            (ContextQueryFeaturesFromSpace
               &self
               Fly
               (Fly atom-micro-crosswind-fragile)))
         3)
      (ContextGuardMatches
         (ContextAnd (type AtomMicroDrone) (ContextAnd (weather atom-crosswind) (payload atom-fragile)))
         (ContextQueryFeaturesFromSpace
            &self
            Fly
            (Fly atom-micro-crosswind-fragile))))
   true)

!(test
   (let (GeneratedContext
           $_statement
           $guard
           $side
           $evidence
           $_projection
           $_score)
      (GeneratedContextForSpaceStatement
         &self
         Fly
         (Fly atom-micro-crosswind-fragile))
      (GeneratedRoute $guard $side $evidence))
   (GeneratedRoute
      (ContextAnd (type AtomMicroDrone) (ContextAnd (weather atom-crosswind) (payload atom-fragile)))
      inside
      (EC 0.0 300.0)))

!(test
   (let (GeneratedContext
           $statement
           $guard
           $side
           $evidence
           $_projection
           $_score)
      (GeneratedContextForSpaceStatement
         &self
         Fly
         (Fly atom-unseen-micro-crosswind-fragile))
      (GeneratedRoute $statement $guard $side $evidence))
   (GeneratedRoute
      (Fly atom-unseen-micro-crosswind-fragile)
      (ContextAnd (type AtomMicroDrone) (ContextAnd (weather atom-crosswind) (payload atom-fragile)))
      inside
      (EC 0.0 300.0)))

!(test
   (let (ContextMinimalityReport
           $_full
           (Ablations $ablations))
      (GeneratedContextMinimalityReportForSpaceStatement
         &self
         Fly
         (Fly atom-unseen-micro-crosswind-fragile))
      (= (length $ablations) 3))
   true)

!(test
   (let (GeneratedContext
           $_statement
           $guard
           $side
           $evidence
           $_projection
           $_score)
      (GeneratedContextForSpaceQuery
         &self
         Fly
         (Fly atom-micro-crosswind-fragile)
         (AtomspaceQueryFeatures atom-micro-crosswind-fragile))
      (GeneratedRoute $guard $side $evidence))
   (GeneratedRoute
      (ContextAnd (type AtomMicroDrone) (ContextAnd (weather atom-crosswind) (payload atom-fragile)))
      inside
      (EC 0.0 300.0)))

!(test
   (GeneratedContextSupport
      (ContextAnd (type AtomMicroDrone) (ContextAnd (weather atom-crosswind) (payload atom-fragile)))
      (AtomspaceQueryFeatures atom-micro-crosswind-fragile)
      (ContextEvidencePacketsFromSpace &self Fly))
   ((SupportPacket
       (Fly atom-micro-crosswind-fragile)
       (EC 0.0 300.0)
       ((type AtomMicroDrone) (weather atom-crosswind) (payload atom-fragile))
       atom-micro-crosswind-fragile-incident)))

!(test
   (ContextTripleStatement
      (GeneratedContextChainingTripleForSpaceQuery
         &self
         Fly
         (Fly atom-micro-crosswind-fragile)
         (AtomspaceQueryFeatures atom-micro-crosswind-fragile)))
   (Fly atom-micro-crosswind-fragile))

!(test
   (let (STV $strength $confidence)
      (ContextTripleProjection
         (GeneratedContextChainingTripleForSpaceQuery
            &self
            Fly
            (Fly atom-micro-crosswind-fragile)
            (AtomspaceQueryFeatures atom-micro-crosswind-fragile)))
      (and
         (ContextBetween $strength 0.006 0.007)
         (ContextBetween $confidence 0.993 0.994)))
   true)

!(test
   (ContextProofGuard
      (ContextTripleProof
         (GeneratedContextChainingTripleForSpaceQuery
            &self
            Fly
            (Fly atom-micro-crosswind-fragile)
            (AtomspaceQueryFeatures atom-micro-crosswind-fragile))))
   (ContextAnd (type AtomMicroDrone) (ContextAnd (weather atom-crosswind) (payload atom-fragile))))

!(test
   (ContextPeTTaChainerResultStatement
      (GeneratedContextPeTTaChainerResultForSpaceQuery
         &self
         Fly
         (Fly atom-micro-crosswind-fragile)
         (AtomspaceQueryFeatures atom-micro-crosswind-fragile)))
   (Fly atom-micro-crosswind-fragile))

!(test
   (let (STV $strength $confidence)
      (ContextPeTTaChainerResultProjection
         (GeneratedContextPeTTaChainerResultForSpaceQuery
            &self
            Fly
            (Fly atom-micro-crosswind-fragile)
            (AtomspaceQueryFeatures atom-micro-crosswind-fragile)))
      (and
         (ContextBetween $strength 0.006 0.007)
         (ContextBetween $confidence 0.993 0.994)))
   true)

!(test
   (ContextPeTTaChainerProofGuard
      (ContextPeTTaChainerResultProof
         (GeneratedContextPeTTaChainerResultForSpaceQuery
            &self
            Fly
            (Fly atom-micro-crosswind-fragile)
            (AtomspaceQueryFeatures atom-micro-crosswind-fragile))))
   (ContextAnd (type AtomMicroDrone) (ContextAnd (weather atom-crosswind) (payload atom-fragile))))

!(test
   (ContextPeTTaChainerProofGuard
      (ContextPeTTaChainerResultProof
         (GeneratedContextPeTTaChainerResultForSpaceStatement
            &self
            Fly
            (Fly atom-micro-crosswind-fragile))))
   (ContextAnd (type AtomMicroDrone) (ContextAnd (weather atom-crosswind) (payload atom-fragile))))

!(test
   (ContextPeTTaChainerResultStatement
      (GeneratedContextPeTTaChainerResultForSpaceStatement
         &self
         Fly
         (Fly atom-unseen-micro-crosswind-fragile)))
   (Fly atom-unseen-micro-crosswind-fragile))

!(test
   (ContextPeTTaChainerResultStatement
      (GeneratedContextCertifiedPeTTaChainerResultForSpaceStatement
         &self
         Fly
         (Fly atom-unseen-micro-crosswind-fragile)))
   (Fly atom-unseen-micro-crosswind-fragile))

!(test
   (ContextCertifiedPeTTaChainerProofGuard
      (ContextPeTTaChainerResultProof
         (GeneratedContextCertifiedPeTTaChainerResultForSpaceStatement
            &self
            Fly
            (Fly atom-unseen-micro-crosswind-fragile))))
   (ContextAnd (type AtomMicroDrone) (ContextAnd (weather atom-crosswind) (payload atom-fragile))))

!(test
   (let (ContextMinimalityReport
           $_full
           (Ablations $ablations))
      (ContextCertifiedPeTTaChainerProofMinimality
         (ContextPeTTaChainerResultProof
            (GeneratedContextCertifiedPeTTaChainerResultForSpaceStatement
               &self
               Fly
               (Fly atom-unseen-micro-crosswind-fragile))))
      (= (length $ablations) 3))
   true)

; Smart dispatch regression: these proof heads must remain inert data
; constructors. Callable wrappers use distinct names such as
; GeneratedContextCertifiedPeTTaChainerResultForSpaceStatement.
!(test
   (context-certified-generated-proof
      (collect-evidence ())
      (generate-context sentinel-guard)
      (score-context sentinel-trace)
      (certify-minimality sentinel-minimality)
      (select-evidence inside (EC 0.0 0.0))
      (project-evidence (STV 0.95 0.0)))
   (context-certified-generated-proof
      (collect-evidence ())
      (generate-context sentinel-guard)
      (score-context sentinel-trace)
      (certify-minimality sentinel-minimality)
      (select-evidence inside (EC 0.0 0.0))
      (project-evidence (STV 0.95 0.0))))
