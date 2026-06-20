!(import! &self context/context_inference_control_beam)

(= (BeamControlLiteralReport)
   (ContextBeamBranchReport
      smoke-grounding
      (Ground smoke-drone)
      (use-smoke-grounding)
      (type SmokeDrone)
      inside
      (EC 10.0 0.0)
      (STV 1.0 0.9)
      1.0
      0.99
      ((SupportPacket
          (Ground smoke-drone)
          (EC 10.0 0.0)
          ((type SmokeDrone))
          smoke-grounded))
      smoke-trace
      smoke-minimality
      (Beam (smoke-node))))

(= (BeamControlLiteralResult)
   (ContextBeamControlResult
      (BeamControlLiteralReport)
      ((ContextBranchDecision execute smoke-grounding (use-smoke-grounding)))
      (cons (BeamControlLiteralReport) ())))

(= (BeamControlLiteralPeTTaChainerResult)
   (call
      (ContextBeamControlResultToPeTTaChainerResult
         (BeamControlLiteralResult))))

(= (BeamControlLiteralProof)
   (call
      (ContextBeamControlledResultProof
         (BeamControlLiteralPeTTaChainerResult))))

!(test
   (call (ContextBeamBranchReportName (BeamControlLiteralReport)))
   smoke-grounding)

!(test
   (call (ContextBeamBranchReportStatement (BeamControlLiteralReport)))
   (Ground smoke-drone))

!(test
   (call (ContextBeamBranchReportAction (BeamControlLiteralReport)))
   (use-smoke-grounding))

!(test
   (call (ContextBeamBranchReportGuard (BeamControlLiteralReport)))
   (type SmokeDrone))

!(test
   (call (ContextBeamBranchReportProjection (BeamControlLiteralReport)))
   (STV 1.0 0.9))

!(test
   (call (ContextBeamBranchReportUtility (BeamControlLiteralReport)))
   0.99)

!(test
   (call (ContextBeamBranchReportMinimality (BeamControlLiteralReport)))
   smoke-minimality)

!(test
   (call (ContextBeamBranchReportBeam (BeamControlLiteralReport)))
   (Beam (smoke-node)))

!(test
   (call (ContextBeamControlResultBest (BeamControlLiteralResult)))
   (BeamControlLiteralReport))

!(test
   (call
      (ContextBeamControlSelectionAuditMargin
         (ContextBeamControlResultSelectionAudit
            (BeamControlLiteralResult))))
   0.99)

!(test
   (call
      (ContextBeamControlledResultStatement
         (BeamControlLiteralPeTTaChainerResult)))
   (Ground smoke-drone))

!(test
   (call
      (ContextBeamControlledProofSelectedBranch
         (BeamControlLiteralProof)))
   smoke-grounding)

!(test
   (call
      (ContextBeamControlledProofSelectedAction
         (BeamControlLiteralProof)))
   (use-smoke-grounding))

!(test
   (call (ContextBeamControlledProofGuard (BeamControlLiteralProof)))
   (type SmokeDrone))

!(test
   (call (ContextBeamControlledProofBeam (BeamControlLiteralProof)))
   (Beam (smoke-node)))

!(test
   (context-beam-controlled-proof
      (select-branch smoke-grounding (use-smoke-grounding))
      (branch-decisions ())
      (ranked-beam-branch-reports ())
      (generate-context (type SmokeDrone))
      (certify-minimality smoke-minimality)
      (project-evidence (STV 1.0 1.0))
      (beam-search (Beam ())))
   (context-beam-controlled-proof
      (select-branch smoke-grounding (use-smoke-grounding))
      (branch-decisions ())
      (ranked-beam-branch-reports ())
      (generate-context (type SmokeDrone))
      (certify-minimality smoke-minimality)
      (project-evidence (STV 1.0 1.0))
      (beam-search (Beam ()))))

(= (BeamControlIntegrationFeatures)
   ((type BeamMicroDrone)))

(= (BeamControlIntegrationFlyPackets)
   ((EvidencePacket
       (Fly beam-micro)
       (EC 0.0 20.0)
       ((type BeamMicroDrone))
       beam-flight-crash)
    (EvidencePacket
       (Fly beam-heavy)
       (EC 20.0 0.0)
       ((type BeamHeavyDrone))
       beam-heavy-flight)))

(= (BeamControlIntegrationGroundPackets)
   ((EvidencePacket
       (Ground beam-micro)
       (EC 20.0 0.0)
       ((type BeamMicroDrone))
       beam-grounding-observed)
    (EvidencePacket
       (Ground beam-heavy)
       (EC 0.0 20.0)
       ((type BeamHeavyDrone))
       beam-heavy-not-grounded)))

(= (BeamControlIntegrationBranches)
   ((ContextBranch
       beam-default-flight
       (Fly beam-micro)
       (BeamControlIntegrationFlyPackets)
       (BeamControlIntegrationFeatures)
       (try-beam-default-flight))
    (ContextBranch
       beam-exception-grounding
       (Ground beam-micro)
       (BeamControlIntegrationGroundPackets)
       (BeamControlIntegrationFeatures)
       (use-beam-grounding-rule))))

!(test
   (ContextBeamControlledResultStatement
      (GeneratedContextBeamControlPeTTaChainerResultForBranches
         (BeamControlIntegrationBranches)
         1
         1))
   (Ground beam-micro))

!(test
   (ContextBeamControlledProofSelectedBranch
      (ContextBeamControlledResultProof
         (GeneratedContextBeamControlPeTTaChainerResultForBranches
            (BeamControlIntegrationBranches)
            1
            1)))
   beam-exception-grounding)

!(test
   (ContextBeamControlSelectionAuditWinner
      (ContextBeamControlResultSelectionAudit
         (GeneratedContextBeamControlForBranches
            (BeamControlIntegrationBranches)
            1
            1)))
   beam-exception-grounding)

!(test
   (ContextBeamBranchReportName
      (ContextBeamControlSelectionAuditRunnerUp
         (ContextBeamControlResultSelectionAudit
            (GeneratedContextBeamControlForBranches
               (BeamControlIntegrationBranches)
               1
               1))))
   beam-default-flight)

!(test
   (once
      (ContextBetween
         (ContextBeamControlSelectionAuditMargin
            (ContextBeamControlResultSelectionAudit
               (GeneratedContextBeamControlForBranches
                  (BeamControlIntegrationBranches)
                  1
                  1)))
         0.82
         0.83))
   True)

!(test
   (ContextBeamControlSelectionAuditWinner
      (ContextBeamControlledProofSelectionAudit
         (ContextBeamControlledResultProof
            (GeneratedContextBeamControlPeTTaChainerResultForBranches
               (BeamControlIntegrationBranches)
               1
               1))))
   beam-exception-grounding)

(= (BeamNeedleQueryFeatures)
   ((type NeedleMicroDrone)
    (weather needle-crosswind)
    (payload needle-fragile)
    (habitat needle-rooftop)))

(= (BeamNeedleGuard)
   (ContextAnd
      (type NeedleMicroDrone)
      (ContextAnd
         (weather needle-crosswind)
         (ContextAnd
            (payload needle-fragile)
            (habitat needle-rooftop)))))

(= (BeamNeedleFlyPackets)
   ((EvidencePacket
       (Fly needle-micro-crosswind-fragile-rooftop)
       (EC 0.0 90.0)
       ((type NeedleMicroDrone)
        (weather needle-crosswind)
        (payload needle-fragile)
        (habitat needle-rooftop))
       needle-exact-flight-incident)
    (EvidencePacket
       (Fly needle-micro-crosswind-fragile-ground)
       (EC 90.0 0.0)
       ((type NeedleMicroDrone)
        (weather needle-crosswind)
        (payload needle-fragile)
        (habitat needle-ground))
       needle-near-ground-flight-ok)
    (EvidencePacket
       (Fly needle-micro-crosswind-normal-rooftop)
       (EC 90.0 0.0)
       ((type NeedleMicroDrone)
        (weather needle-crosswind)
        (payload needle-normal)
        (habitat needle-rooftop))
       needle-near-normal-flight-ok)
    (EvidencePacket
       (Fly needle-micro-calm-fragile-rooftop)
       (EC 90.0 0.0)
       ((type NeedleMicroDrone)
        (weather needle-calm)
        (payload needle-fragile)
        (habitat needle-rooftop))
       needle-near-calm-flight-ok)
    (EvidencePacket
       (Fly needle-heavy-crosswind-fragile-rooftop)
       (EC 90.0 0.0)
       ((type NeedleHeavyDrone)
        (weather needle-crosswind)
        (payload needle-fragile)
        (habitat needle-rooftop))
       needle-near-heavy-flight-ok)))

(= (BeamNeedleGroundPackets)
   ((EvidencePacket
       (Ground needle-micro-crosswind-fragile-rooftop)
       (EC 45.0 0.0)
       ((type NeedleMicroDrone)
        (weather needle-crosswind)
        (payload needle-fragile)
        (habitat needle-rooftop))
       needle-exact-grounding-success)
    (EvidencePacket
       (Ground needle-micro-crosswind-fragile-ground)
       (EC 0.0 30.0)
       ((type NeedleMicroDrone)
        (weather needle-crosswind)
        (payload needle-fragile)
        (habitat needle-ground))
       needle-ground-site-not-grounded)
    (EvidencePacket
       (Ground needle-micro-crosswind-normal-rooftop)
       (EC 0.0 30.0)
       ((type NeedleMicroDrone)
        (weather needle-crosswind)
        (payload needle-normal)
        (habitat needle-rooftop))
       needle-normal-payload-not-grounded)
    (EvidencePacket
       (Ground needle-micro-calm-fragile-rooftop)
       (EC 0.0 30.0)
       ((type NeedleMicroDrone)
        (weather needle-calm)
        (payload needle-fragile)
        (habitat needle-rooftop))
       needle-calm-not-grounded)
    (EvidencePacket
       (Ground needle-heavy-crosswind-fragile-rooftop)
       (EC 0.0 30.0)
       ((type NeedleHeavyDrone)
        (weather needle-crosswind)
        (payload needle-fragile)
        (habitat needle-rooftop))
       needle-heavy-not-grounded)))

(= (BeamNeedleInspectPackets)
   ((EvidencePacket
       (Inspect needle-micro-crosswind-fragile-rooftop)
       (EC 4.0 2.0)
       ((type NeedleMicroDrone)
        (weather needle-crosswind)
        (payload needle-fragile)
        (habitat needle-rooftop))
       needle-weak-inspection-hit)
    (EvidencePacket
       (Inspect needle-micro-crosswind-fragile-ground)
       (EC 3.0 4.0)
       ((type NeedleMicroDrone)
        (weather needle-crosswind)
        (payload needle-fragile)
        (habitat needle-ground))
       needle-weak-inspection-ground)
    (EvidencePacket
       (Inspect needle-heavy-crosswind-fragile-rooftop)
       (EC 2.0 5.0)
       ((type NeedleHeavyDrone)
        (weather needle-crosswind)
        (payload needle-fragile)
        (habitat needle-rooftop))
       needle-weak-inspection-heavy)))

(= (BeamNeedleBranches)
   ((ContextBranch
       beam-needle-default-flight
       (Fly needle-micro-crosswind-fragile-rooftop)
       (BeamNeedleFlyPackets)
       (BeamNeedleQueryFeatures)
       (try-needle-default-flight))
    (ContextBranch
       beam-needle-grounding
       (Ground needle-micro-crosswind-fragile-rooftop)
       (BeamNeedleGroundPackets)
       (BeamNeedleQueryFeatures)
       (use-needle-grounding-rule))
    (ContextBranch
       beam-needle-inspection
       (Inspect needle-micro-crosswind-fragile-rooftop)
       (BeamNeedleInspectPackets)
       (BeamNeedleQueryFeatures)
       (ask-needle-inspection))))

!(test
   (let* (($result
            (GeneratedContextBeamControlPeTTaChainerResultForBranches
               (BeamNeedleBranches)
               4
               8))
          ($proof (ContextBeamControlledResultProof $result))
          ($audit (ContextBeamControlledProofSelectionAudit $proof)))
      (and
         (== (ContextBeamControlledProofSelectedBranch $proof)
             beam-needle-grounding)
         (and
            (== (ContextBeamControlledProofGuard $proof)
                (BeamNeedleGuard))
            (and
               (== (ContextBeamControlledResultStatement $result)
                   (Ground needle-micro-crosswind-fragile-rooftop))
               (and
                  (is-member
                     (ContextBranchDecision prune
                        beam-needle-default-flight
                        (try-needle-default-flight))
                     (ContextBeamControlledProofDecisions $proof))
                  (== (ContextBeamControlSelectionAuditWinner $audit)
                      beam-needle-grounding))))))
   True)
