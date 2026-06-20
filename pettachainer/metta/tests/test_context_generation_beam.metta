!(import! &self context/context_generation_beam)

(= (BeamTripleFlyPackets)
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

(= (BeamTripleQueryFeatures)
   ((type MicroDrone) (weather crosswind) (payload fragile)))

(= (BeamQuadFlyPackets)
   ((EvidencePacket
       (Fly quad-micro-crosswind-fragile-ground)
       (EC 300.0 0.0)
       ((type QuadMicroDrone) (weather quad-crosswind) (payload quad-fragile) (habitat quad-ground))
       quad-micro-crosswind-fragile-ground-flight)
    (EvidencePacket
       (Fly quad-micro-crosswind-normal-rooftop)
       (EC 300.0 0.0)
       ((type QuadMicroDrone) (weather quad-crosswind) (payload quad-normal) (habitat quad-rooftop))
       quad-micro-crosswind-normal-rooftop-flight)
    (EvidencePacket
       (Fly quad-micro-calm-fragile-rooftop)
       (EC 300.0 0.0)
       ((type QuadMicroDrone) (weather quad-calm) (payload quad-fragile) (habitat quad-rooftop))
       quad-micro-calm-fragile-rooftop-flight)
    (EvidencePacket
       (Fly quad-heavy-crosswind-fragile-rooftop)
       (EC 300.0 0.0)
       ((type QuadHeavyDrone) (weather quad-crosswind) (payload quad-fragile) (habitat quad-rooftop))
       quad-heavy-crosswind-fragile-rooftop-flight)
    (EvidencePacket
       (Fly quad-micro-crosswind-fragile-rooftop)
       (EC 0.0 300.0)
       ((type QuadMicroDrone) (weather quad-crosswind) (payload quad-fragile) (habitat quad-rooftop))
       quad-micro-crosswind-fragile-rooftop-incident)))

(= (BeamQuadQueryFeatures)
   ((type QuadMicroDrone) (weather quad-crosswind) (payload quad-fragile) (habitat quad-rooftop)))

(= (BeamQuadGuard)
   (ContextAnd
      (type QuadMicroDrone)
      (ContextAnd
         (weather quad-crosswind)
         (ContextAnd (payload quad-fragile) (habitat quad-rooftop)))))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly beam-atom-micro-crosswind-normal)
      (EC 300.0 0.0)
      ((type BeamAtomMicroDrone) (weather beam-atom-crosswind) (payload beam-atom-normal))
      beam-atom-micro-crosswind-normal-flight))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly beam-atom-micro-calm-fragile)
      (EC 300.0 0.0)
      ((type BeamAtomMicroDrone) (weather beam-atom-calm) (payload beam-atom-fragile))
      beam-atom-micro-calm-fragile-flight))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly beam-atom-heavy-crosswind-fragile)
      (EC 300.0 0.0)
      ((type BeamAtomHeavyDrone) (weather beam-atom-crosswind) (payload beam-atom-fragile))
      beam-atom-heavy-crosswind-fragile-flight))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly beam-atom-heavy-calm-normal)
      (EC 300.0 0.0)
      ((type BeamAtomHeavyDrone) (weather beam-atom-calm) (payload beam-atom-normal))
      beam-atom-heavy-calm-normal-flight))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly beam-atom-micro-crosswind-fragile)
      (EC 0.0 300.0)
      ((type BeamAtomMicroDrone) (weather beam-atom-crosswind) (payload beam-atom-fragile))
      beam-atom-micro-crosswind-fragile-incident))

!(add-atom &self
   (ContextStatementFeatures
      Fly
      (Fly beam-atom-unseen-micro-crosswind-fragile)
      ((type BeamAtomMicroDrone) (weather beam-atom-crosswind) (payload beam-atom-fragile))))

(= (BeamAtomspaceQueryFeatures)
   ((type BeamAtomMicroDrone) (weather beam-atom-crosswind) (payload beam-atom-fragile)))

!(test
   (let (ContextBeamAnswer
           $_statement
           $guard
           $side
           $evidence
           $_projection
           $_support
           $_trace
           $_beam)
      (context_beam_for_query
         (Fly micro-crosswind-fragile)
         (BeamTripleFlyPackets)
         (BeamTripleQueryFeatures)
         3
         5)
      (BeamRoute $guard $side $evidence))
   (BeamRoute
      (ContextAnd (type MicroDrone) (ContextAnd (weather crosswind) (payload fragile)))
      inside
      (EC 0.0 300.0)))

!(test
   (is-member (BeamQuadGuard) (GeneratedContextGuards (BeamQuadFlyPackets)))
   false)

!(test
   (length (ContextGuardAtoms (BeamQuadGuard)))
   4)

!(test
   (let (ContextBeamAnswer
           $_statement
           $guard
           $side
           $evidence
           $_projection
           $_support
           $_trace
           $_beam)
      (context_beam_for_query
         (Fly quad-micro-crosswind-fragile-rooftop)
         (BeamQuadFlyPackets)
         (BeamQuadQueryFeatures)
         4
         5)
      (BeamRoute $guard $side $evidence))
   (BeamRoute
      (BeamQuadGuard)
      inside
      (EC 0.0 300.0)))

!(test
   (let (ContextMinimalityReport
           (FullTrace
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
           (Ablations $ablations))
      (ContextBeamCertifiedPeTTaChainerProofMinimality
         (ContextPeTTaChainerResultProof
            (ContextBeamCertifiedPeTTaChainerResultForQuery
               (Fly quad-micro-crosswind-fragile-rooftop)
               (BeamQuadFlyPackets)
               (BeamQuadQueryFeatures)
               4
               5)))
      (and
         (= (length $ablations) 4)
         (ContextBetween $score 0.969 0.971)))
   true)

!(test
   (let (ContextBeamAnswer
           $_statement
           $_guard
           $_side
           $_evidence
           (STV $strength $confidence)
           $_support
           $_trace
           $_beam)
      (context_beam_for_query
         (Fly micro-crosswind-fragile)
         (BeamTripleFlyPackets)
         (BeamTripleQueryFeatures)
         3
         5)
      (and
         (ContextBetween $strength 0.006 0.007)
         (ContextBetween $confidence 0.993 0.994)))
   true)

!(test
   (let (ContextBeamAnswer
           $_statement
           $_guard
           $_side
           $_evidence
           $_projection
           $support
           $_trace
           $_beam)
      (context_beam_for_query
         (Fly micro-crosswind-fragile)
         (BeamTripleFlyPackets)
         (BeamTripleQueryFeatures)
         3
         5)
      $support)
   ((SupportPacket
       (Fly micro-crosswind-fragile)
       (EC 0.0 300.0)
       ((type MicroDrone) (weather crosswind) (payload fragile))
       micro-crosswind-fragile-incident)))

!(test
   (let (ContextBeamAnswer
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
              (Score $score))
           $_beam)
      (context_beam_for_query
         (Fly micro-crosswind-fragile)
         (BeamTripleFlyPackets)
         (BeamTripleQueryFeatures)
         3
         5)
      (and
         (ContextBetween $reduction 0.399 0.401)
         (ContextBetween $score 1.009 1.011)))
   true)

!(test
   (let* (((ScoredGuard $pure-guard $_pure-score)
             (BestGeneratedContextGuard (BeamTripleFlyPackets) (BeamTripleQueryFeatures)))
          ((ContextBeamAnswer
              $_statement
              $beam-guard
              $_side
              $_evidence
              $_projection
              $_support
              $_trace
              $_beam)
             (context_beam_for_query
                (Fly micro-crosswind-fragile)
                (BeamTripleFlyPackets)
                (BeamTripleQueryFeatures)
                3
                5)))
      (= $pure-guard $beam-guard))
   true)

!(test
   (let (ContextBeamAnswer
           $_statement
           $guard
           $side
           $evidence
           $_projection
           $_support
           $_trace
           $_beam)
      (ContextBeamForSpaceQuery
         &self
         Fly
         (Fly beam-atom-micro-crosswind-fragile)
         (BeamAtomspaceQueryFeatures)
         3
         5)
      (BeamRoute $guard $side $evidence))
   (BeamRoute
      (ContextAnd
         (type BeamAtomMicroDrone)
         (ContextAnd (weather beam-atom-crosswind) (payload beam-atom-fragile)))
      inside
      (EC 0.0 300.0)))

!(test
   (and
      (= (length
            (ContextQueryFeaturesFromSpace
               &self
               Fly
               (Fly beam-atom-micro-crosswind-fragile)))
         3)
      (ContextGuardMatches
         (ContextAnd
            (type BeamAtomMicroDrone)
            (ContextAnd (weather beam-atom-crosswind) (payload beam-atom-fragile)))
         (ContextQueryFeaturesFromSpace
            &self
            Fly
            (Fly beam-atom-micro-crosswind-fragile))))
   true)

!(test
   (let (ContextBeamAnswer
           $_statement
           $guard
           $side
           $evidence
           $_projection
           $_support
           $_trace
           $_beam)
      (ContextBeamForSpaceStatement
         &self
         Fly
         (Fly beam-atom-micro-crosswind-fragile)
         3
         5)
      (BeamRoute $guard $side $evidence))
   (BeamRoute
      (ContextAnd
         (type BeamAtomMicroDrone)
         (ContextAnd (weather beam-atom-crosswind) (payload beam-atom-fragile)))
      inside
      (EC 0.0 300.0)))

!(test
   (let (ContextBeamAnswer
           $statement
           $guard
           $side
           $evidence
           $_projection
           $_support
           $_trace
           $_beam)
      (ContextBeamForSpaceStatement
         &self
         Fly
         (Fly beam-atom-unseen-micro-crosswind-fragile)
         3
         5)
      (BeamRoute $statement $guard $side $evidence))
   (BeamRoute
      (Fly beam-atom-unseen-micro-crosswind-fragile)
      (ContextAnd
         (type BeamAtomMicroDrone)
         (ContextAnd (weather beam-atom-crosswind) (payload beam-atom-fragile)))
      inside
      (EC 0.0 300.0)))

!(test
   (ContextTripleStatement
      (ContextBeamChainingTripleForSpaceQuery
         &self
         Fly
         (Fly beam-atom-micro-crosswind-fragile)
         (BeamAtomspaceQueryFeatures)
         3
         5))
   (Fly beam-atom-micro-crosswind-fragile))

!(test
   (let (STV $strength $confidence)
      (ContextTripleProjection
         (ContextBeamChainingTripleForSpaceQuery
            &self
            Fly
            (Fly beam-atom-micro-crosswind-fragile)
            (BeamAtomspaceQueryFeatures)
            3
            5))
      (and
         (ContextBetween $strength 0.006 0.007)
         (ContextBetween $confidence 0.993 0.994)))
   true)

!(test
   (ContextBeamProofGuard
      (ContextTripleProof
         (ContextBeamChainingTripleForSpaceQuery
            &self
            Fly
            (Fly beam-atom-micro-crosswind-fragile)
            (BeamAtomspaceQueryFeatures)
            3
            5)))
   (ContextAnd
      (type BeamAtomMicroDrone)
      (ContextAnd (weather beam-atom-crosswind) (payload beam-atom-fragile))))

!(test
   (ContextPeTTaChainerResultStatement
      (ContextBeamPeTTaChainerResultForSpaceQuery
         &self
         Fly
         (Fly beam-atom-micro-crosswind-fragile)
         (BeamAtomspaceQueryFeatures)
         3
         5))
   (Fly beam-atom-micro-crosswind-fragile))

!(test
   (let (STV $strength $confidence)
      (ContextPeTTaChainerResultProjection
         (ContextBeamPeTTaChainerResultForSpaceQuery
            &self
            Fly
            (Fly beam-atom-micro-crosswind-fragile)
            (BeamAtomspaceQueryFeatures)
            3
            5))
      (and
         (ContextBetween $strength 0.006 0.007)
         (ContextBetween $confidence 0.993 0.994)))
   true)

!(test
   (ContextBeamPeTTaChainerProofGuard
      (ContextPeTTaChainerResultProof
         (ContextBeamPeTTaChainerResultForSpaceQuery
            &self
            Fly
            (Fly beam-atom-micro-crosswind-fragile)
            (BeamAtomspaceQueryFeatures)
            3
            5)))
   (ContextAnd
      (type BeamAtomMicroDrone)
      (ContextAnd (weather beam-atom-crosswind) (payload beam-atom-fragile))))

!(test
   (ContextBeamPeTTaChainerProofGuard
      (ContextPeTTaChainerResultProof
         (ContextBeamPeTTaChainerResultForSpaceStatement
            &self
            Fly
            (Fly beam-atom-micro-crosswind-fragile)
            3
            5)))
   (ContextAnd
      (type BeamAtomMicroDrone)
      (ContextAnd (weather beam-atom-crosswind) (payload beam-atom-fragile))))

!(test
   (ContextPeTTaChainerResultStatement
      (ContextBeamPeTTaChainerResultForSpaceStatement
         &self
         Fly
         (Fly beam-atom-unseen-micro-crosswind-fragile)
         3
         5))
   (Fly beam-atom-unseen-micro-crosswind-fragile))

!(test
   (ContextPeTTaChainerResultStatement
      (ContextBeamCertifiedPeTTaChainerResultForSpaceStatement
         &self
         Fly
         (Fly beam-atom-unseen-micro-crosswind-fragile)
         3
         5))
   (Fly beam-atom-unseen-micro-crosswind-fragile))

!(test
   (ContextBeamCertifiedPeTTaChainerProofGuard
      (ContextPeTTaChainerResultProof
         (ContextBeamCertifiedPeTTaChainerResultForSpaceStatement
            &self
            Fly
            (Fly beam-atom-unseen-micro-crosswind-fragile)
            3
            5)))
   (ContextAnd
      (type BeamAtomMicroDrone)
      (ContextAnd (weather beam-atom-crosswind) (payload beam-atom-fragile))))

!(test
   (let (ContextMinimalityReport
           $_full
           (Ablations $ablations))
      (ContextBeamCertifiedPeTTaChainerProofMinimality
         (ContextPeTTaChainerResultProof
            (ContextBeamCertifiedPeTTaChainerResultForSpaceStatement
               &self
               Fly
               (Fly beam-atom-unseen-micro-crosswind-fragile)
               3
               5)))
      (= (length $ablations) 3))
   true)

!(test
   (let (Beam $reports)
      (ContextBeamCertifiedPeTTaChainerProofBeam
         (ContextPeTTaChainerResultProof
            (ContextBeamCertifiedPeTTaChainerResultForSpaceStatement
               &self
               Fly
               (Fly beam-atom-unseen-micro-crosswind-fragile)
               3
                5)))
      (= (length $reports) 5))
   true)

; Smart dispatch regression for the Prolog-backed proof constructor. This head
; must stay inert data; callable APIs use ContextBeamCertified... names.
!(test
   (context-certified-beam-generated-proof
      (collect-evidence ())
      (generate-context sentinel-guard)
      (score-context sentinel-trace)
      (certify-minimality sentinel-minimality)
      (select-evidence inside (EC 0.0 0.0))
      (project-evidence (STV 0.95 0.0))
      (Beam ()))
   (context-certified-beam-generated-proof
      (collect-evidence ())
      (generate-context sentinel-guard)
      (score-context sentinel-trace)
      (certify-minimality sentinel-minimality)
      (select-evidence inside (EC 0.0 0.0))
      (project-evidence (STV 0.95 0.0))
      (Beam ())))
