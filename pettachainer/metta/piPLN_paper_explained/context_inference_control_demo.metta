; Generated-context inference-control demo.
;
; Demos sections 14.1-14.3: branch selection driven by generated-context utility.
; The contradicted default-flight branch is pruned and the grounding branch
; executes.
;
; The PLN inference-control experiment in the trueagi-io/chaining repo represents
; possible recursive calls as delayed branches, scores them, and executes the
; best one. This demo does the same style of control with generated contexts:
; each branch gets a local evidence context and an STV projection, then the
; controller executes the branch with the strongest projected viability.

!(import! &self context/context_inference_control)

(= (ControlDemoQueryFeatures)
   ((type MicroDrone) (weather crosswind) (payload fragile)))

(= (ControlDemoFlyPackets)
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

(= (ControlDemoGroundPackets)
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

(= (ControlDemoInspectPackets)
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

(= (ControlDemoBranches)
   ((ContextBranch
       default-flight
       (Fly micro-crosswind-fragile)
       (ControlDemoFlyPackets)
       (ControlDemoQueryFeatures)
       (try-default-flight-rule))
    (ContextBranch
       exception-grounding
       (Ground micro-crosswind-fragile)
       (ControlDemoGroundPackets)
       (ControlDemoQueryFeatures)
       (use-fragile-grounding-rule))
    (ContextBranch
       weak-inspection
       (Inspect micro-crosswind-fragile)
       (ControlDemoInspectPackets)
       (ControlDemoQueryFeatures)
       (ask-for-inspection))))

; Raw controller output (sections 14.1-14.3): best branch, execute/prune
; decisions, and all branch reports with generated contexts, projections, traces,
; support, and ablations.
!(GeneratedContextControlForBranches (ControlDemoBranches))

; Compact selection audit: winner, action, best report, runner-up, margin, and
; execute/prune decisions.
!(ContextControlResultSelectionAudit
   (GeneratedContextControlForBranches (ControlDemoBranches)))

!(ContextControlSelectionAuditMargin
   (ContextControlResultSelectionAudit
      (GeneratedContextControlForBranches (ControlDemoBranches))))

; PeTTaChainer result convention:
;   (: proof-tree selected-statement projected-truth-value)
!(GeneratedContextControlPeTTaChainerResultForBranches (ControlDemoBranches))

; The selected proof constructor is inert data under PeTTa Smart Dispatch.
!(ContextControlledProofSelectedBranch
   (ContextControlledResultProof
      (GeneratedContextControlPeTTaChainerResultForBranches
         (ControlDemoBranches))))

; Atomspace-driven version: candidate branches, evidence packets, and query
; features are facts. The controller discovers the branch list with
; match/collapse, builds each branch's generated context, then executes one.
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

!(GeneratedContextControlForSpace &self FlightSafetyControl)

!(GeneratedContextControlSelectionAuditForSpace &self FlightSafetyControl)

!(GeneratedContextControlPeTTaChainerResultForSpace &self FlightSafetyControl)

!(ContextControlledProofSelectedBranch
   (ContextControlledResultProof
      (GeneratedContextControlPeTTaChainerResultForSpace
         &self
         FlightSafetyControl)))
