!(import! &self context/context_inference_control)

(= (ControlQueryFeatures)
   ((type MicroDrone) (weather crosswind) (payload fragile)))

(= (ControlFlyPackets)
   ((EvidencePacket
       (Fly micro-crosswind-normal)
       (EC 300.0 0.0)
       ((type MicroDrone) (weather crosswind) (payload normal))
       default-flight-micro-crosswind-normal)
    (EvidencePacket
       (Fly micro-calm-fragile)
       (EC 300.0 0.0)
       ((type MicroDrone) (weather calm) (payload fragile))
       default-flight-micro-calm-fragile)
    (EvidencePacket
       (Fly heavy-crosswind-fragile)
       (EC 300.0 0.0)
       ((type HeavyDrone) (weather crosswind) (payload fragile))
       default-flight-heavy-crosswind-fragile)
    (EvidencePacket
       (Fly micro-crosswind-fragile)
       (EC 0.0 300.0)
       ((type MicroDrone) (weather crosswind) (payload fragile))
       exception-crash-micro-crosswind-fragile)))

(= (ControlGroundPackets)
   ((EvidencePacket
       (Ground micro-crosswind-fragile)
       (EC 40.0 0.0)
       ((type MicroDrone) (weather crosswind) (payload fragile))
       exception-grounding-observed)
    (EvidencePacket
       (Ground micro-calm-fragile)
       (EC 0.0 50.0)
       ((type MicroDrone) (weather calm) (payload fragile))
       calm-fragile-not-grounded)
    (EvidencePacket
       (Ground heavy-crosswind-fragile)
       (EC 0.0 60.0)
       ((type HeavyDrone) (weather crosswind) (payload fragile))
       heavy-crosswind-not-grounded)
    (EvidencePacket
       (Ground micro-crosswind-normal)
       (EC 0.0 70.0)
       ((type MicroDrone) (weather crosswind) (payload normal))
       normal-payload-not-grounded)))

(= (ControlInspectPackets)
   ((EvidencePacket
       (Inspect micro-crosswind-fragile)
       (EC 4.0 1.0)
       ((type MicroDrone) (weather crosswind) (payload fragile))
       weak-inspection-hit)
    (EvidencePacket
       (Inspect micro-calm-fragile)
       (EC 2.0 3.0)
       ((type MicroDrone) (weather calm) (payload fragile))
       weak-inspection-miss)
    (EvidencePacket
       (Inspect heavy-crosswind-fragile)
       (EC 1.0 4.0)
       ((type HeavyDrone) (weather crosswind) (payload fragile))
       weak-inspection-heavy)))

(= (ControlBranchCandidates)
   ((ContextBranch
       default-flight
       (Fly micro-crosswind-fragile)
       (ControlFlyPackets)
       (ControlQueryFeatures)
       (try-default-flight-rule))
    (ContextBranch
       exception-grounding
       (Ground micro-crosswind-fragile)
       (ControlGroundPackets)
       (ControlQueryFeatures)
       (use-fragile-grounding-rule))
    (ContextBranch
       weak-inspection
       (Inspect micro-crosswind-fragile)
       (ControlInspectPackets)
       (ControlQueryFeatures)
       (ask-for-inspection))))

!(test
   (ContextBranchReportName
      (ContextControlResultBest
         (GeneratedContextControlForBranches (ControlBranchCandidates))))
   exception-grounding)

!(test
   (ContextBranchReportStatement
      (ContextControlResultBest
         (GeneratedContextControlForBranches (ControlBranchCandidates))))
   (Ground micro-crosswind-fragile))

!(test
   (ContextControlledResultStatement
      (GeneratedContextControlPeTTaChainerResultForBranches
         (ControlBranchCandidates)))
   (Ground micro-crosswind-fragile))

!(test
   (ContextControlledProofSelectedBranch
      (ContextControlledResultProof
         (GeneratedContextControlPeTTaChainerResultForBranches
            (ControlBranchCandidates))))
   exception-grounding)

!(test
   (is-member
      (ContextBranchDecision execute exception-grounding (use-fragile-grounding-rule))
      (ContextControlResultDecisions
         (GeneratedContextControlForBranches (ControlBranchCandidates))))
   True)

!(test
   (is-member
      (ContextBranchDecision prune default-flight (try-default-flight-rule))
      (ContextControlResultDecisions
         (GeneratedContextControlForBranches (ControlBranchCandidates))))
   True)

!(test
   (length
      (ContextControlledProofReports
         (ContextControlledResultProof
            (GeneratedContextControlPeTTaChainerResultForBranches
               (ControlBranchCandidates)))))
   3)

!(test
   (ContextBranchReportName
      (ContextFirstBranchReport
         (ContextControlledProofReports
            (ContextControlledResultProof
               (GeneratedContextControlPeTTaChainerResultForBranches
                  (ControlBranchCandidates))))))
   exception-grounding)

!(test
   (ContextControlSelectionAuditWinner
      (ContextControlResultSelectionAudit
         (GeneratedContextControlForBranches (ControlBranchCandidates))))
   exception-grounding)

!(test
   (ContextBranchReportName
      (ContextControlSelectionAuditRunnerUp
         (ContextControlResultSelectionAudit
            (GeneratedContextControlForBranches (ControlBranchCandidates)))))
   weak-inspection)

!(test
   (ContextBetween
      (ContextControlSelectionAuditMargin
         (ContextControlResultSelectionAudit
            (GeneratedContextControlForBranches (ControlBranchCandidates))))
      0.34
      0.35)
   True)

!(test
   (ContextControlSelectionAuditWinner
      (ContextControlledProofSelectionAudit
         (ContextControlledResultProof
            (GeneratedContextControlPeTTaChainerResultForBranches
               (ControlBranchCandidates)))))
   exception-grounding)

!(test
   (context-controlled-proof
      (select-branch exception-grounding (use-fragile-grounding-rule))
      (branch-decisions ())
      (ranked-branch-reports ())
      (generate-context (weather crosswind))
      (certify-minimality empty-report)
      (project-evidence (STV 1.0 1.0)))
   (context-controlled-proof
      (select-branch exception-grounding (use-fragile-grounding-rule))
      (branch-decisions ())
      (ranked-branch-reports ())
      (generate-context (weather crosswind))
      (certify-minimality empty-report)
      (project-evidence (STV 1.0 1.0))))

!(add-atom &self
   (ContextControlCandidate
      FlightSafetyControl
      space-default-flight
      (Fly space-micro-crosswind-fragile)
      (try-space-default-flight-rule)))
!(add-atom &self
   (ContextControlCandidate
      FlightSafetyControl
      space-exception-grounding
      (Ground space-micro-crosswind-fragile)
      (use-space-fragile-grounding-rule)))
!(add-atom &self
   (ContextControlCandidate
      FlightSafetyControl
      space-weak-inspection
      (Inspect space-micro-crosswind-fragile)
      (ask-space-inspection)))

!(add-atom &self
   (ContextControlQueryFeatures
      FlightSafetyControl
      space-default-flight
      ((type SpaceMicroDrone) (weather space-crosswind) (payload space-fragile))))
!(add-atom &self
   (ContextControlQueryFeatures
      FlightSafetyControl
      space-exception-grounding
      ((type SpaceMicroDrone) (weather space-crosswind) (payload space-fragile))))
!(add-atom &self
   (ContextControlQueryFeatures
      FlightSafetyControl
      space-weak-inspection
      ((type SpaceMicroDrone) (weather space-crosswind) (payload space-fragile))))

!(add-atom &self
   (ContextControlEvidence
      FlightSafetyControl
      space-default-flight
      (Fly space-micro-crosswind-normal)
      (EC 300.0 0.0)
      ((type SpaceMicroDrone) (weather space-crosswind) (payload space-normal))
      space-default-flight-normal))
!(add-atom &self
   (ContextControlEvidence
      FlightSafetyControl
      space-default-flight
      (Fly space-micro-calm-fragile)
      (EC 300.0 0.0)
      ((type SpaceMicroDrone) (weather space-calm) (payload space-fragile))
      space-default-flight-calm))
!(add-atom &self
   (ContextControlEvidence
      FlightSafetyControl
      space-default-flight
      (Fly space-heavy-crosswind-fragile)
      (EC 300.0 0.0)
      ((type SpaceHeavyDrone) (weather space-crosswind) (payload space-fragile))
      space-default-flight-heavy))
!(add-atom &self
   (ContextControlEvidence
      FlightSafetyControl
      space-default-flight
      (Fly space-micro-crosswind-fragile)
      (EC 0.0 300.0)
      ((type SpaceMicroDrone) (weather space-crosswind) (payload space-fragile))
      space-default-flight-crash))

!(add-atom &self
   (ContextControlEvidence
      FlightSafetyControl
      space-exception-grounding
      (Ground space-micro-crosswind-fragile)
      (EC 40.0 0.0)
      ((type SpaceMicroDrone) (weather space-crosswind) (payload space-fragile))
      space-grounding-observed))
!(add-atom &self
   (ContextControlEvidence
      FlightSafetyControl
      space-exception-grounding
      (Ground space-micro-calm-fragile)
      (EC 0.0 50.0)
      ((type SpaceMicroDrone) (weather space-calm) (payload space-fragile))
      space-calm-not-grounded))
!(add-atom &self
   (ContextControlEvidence
      FlightSafetyControl
      space-exception-grounding
      (Ground space-heavy-crosswind-fragile)
      (EC 0.0 60.0)
      ((type SpaceHeavyDrone) (weather space-crosswind) (payload space-fragile))
      space-heavy-not-grounded))
!(add-atom &self
   (ContextControlEvidence
      FlightSafetyControl
      space-exception-grounding
      (Ground space-micro-crosswind-normal)
      (EC 0.0 70.0)
      ((type SpaceMicroDrone) (weather space-crosswind) (payload space-normal))
      space-normal-not-grounded))

!(add-atom &self
   (ContextControlEvidence
      FlightSafetyControl
      space-weak-inspection
      (Inspect space-micro-crosswind-fragile)
      (EC 4.0 1.0)
      ((type SpaceMicroDrone) (weather space-crosswind) (payload space-fragile))
      space-weak-inspection-hit))
!(add-atom &self
   (ContextControlEvidence
      FlightSafetyControl
      space-weak-inspection
      (Inspect space-micro-calm-fragile)
      (EC 2.0 3.0)
      ((type SpaceMicroDrone) (weather space-calm) (payload space-fragile))
      space-weak-inspection-miss))
!(add-atom &self
   (ContextControlEvidence
      FlightSafetyControl
      space-weak-inspection
      (Inspect space-heavy-crosswind-fragile)
      (EC 1.0 4.0)
      ((type SpaceHeavyDrone) (weather space-crosswind) (payload space-fragile))
      space-weak-inspection-heavy))

!(test
   (length (ContextControlBranchesFromSpace &self FlightSafetyControl))
   3)

!(test
   (ContextBranchReportName
      (ContextFirstBranchReport
         (ContextControlResultReports
            (GeneratedContextControlForSpace &self FlightSafetyControl))))
   space-exception-grounding)

!(test
   (ContextBranchReportName
      (ContextControlResultBest
         (GeneratedContextControlForSpace &self FlightSafetyControl)))
   space-exception-grounding)

!(test
   (ContextControlledResultStatement
      (GeneratedContextControlPeTTaChainerResultForSpace &self FlightSafetyControl))
   (Ground space-micro-crosswind-fragile))

!(test
   (ContextControlledProofSelectedAction
      (ContextControlledResultProof
         (GeneratedContextControlPeTTaChainerResultForSpace &self FlightSafetyControl)))
   (use-space-fragile-grounding-rule))

!(test
   (is-member
      (ContextBranchDecision prune space-default-flight (try-space-default-flight-rule))
      (ContextControlResultDecisions
         (GeneratedContextControlForSpace &self FlightSafetyControl)))
   True)

!(test
   (ContextControlSelectionAuditWinner
      (GeneratedContextControlSelectionAuditForSpace &self FlightSafetyControl))
   space-exception-grounding)
