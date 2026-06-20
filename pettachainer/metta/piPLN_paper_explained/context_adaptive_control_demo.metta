; Adaptive generated-context inference-control demo.
;
; Demos revision as inference control (sections 11, 14.3). Before exception
; evidence the controller backs the default branch; after crosswind/fragile
; incident evidence arrives it regenerates the local context and flips to
; grounding. The clearest executable answer to "contexts generated on the spot".
;
; This shows the "generated on the spot" claim in a changing atomspace. The
; same controller first selects a broad default-flight branch. After new
; crosswind/fragile incident evidence is added, the generated local context
; changes and the controller flips to the grounding branch.

!(import! &self context/context_inference_control)

!(add-atom &self
   (ContextControlCandidate
      AdaptiveFlightControl
      adaptive-default-flight
      (Fly adaptive-micro)
      (try-adaptive-default-flight)))
!(add-atom &self
   (ContextControlCandidate
      AdaptiveFlightControl
      adaptive-grounding
      (Ground adaptive-micro)
      (use-adaptive-grounding-rule)))

!(add-atom &self
   (ContextControlQueryFeatures
      AdaptiveFlightControl
      adaptive-default-flight
      ((type AdaptiveMicroDrone)
       (weather adaptive-crosswind)
       (payload adaptive-fragile))))
!(add-atom &self
   (ContextControlQueryFeatures
      AdaptiveFlightControl
      adaptive-grounding
      ((type AdaptiveMicroDrone)
       (weather adaptive-crosswind)
       (payload adaptive-fragile))))

!(add-atom &self
   (ContextControlEvidence
      AdaptiveFlightControl
      adaptive-default-flight
      (Fly adaptive-micro)
      (EC 50.0 0.0)
      ((type AdaptiveMicroDrone)
       (weather adaptive-calm)
       (payload adaptive-normal))
      adaptive-baseline-flight-safe))
!(add-atom &self
   (ContextControlEvidence
      AdaptiveFlightControl
      adaptive-grounding
      (Ground adaptive-micro)
      (EC 0.0 20.0)
      ((type AdaptiveMicroDrone)
       (weather adaptive-calm)
       (payload adaptive-normal))
      adaptive-baseline-grounding-unneeded))

; Before the exception evidence arrives, the broad type-level generated context
; supports the default branch.
!(println!
   (before-winner
      (ContextControlSelectionAuditWinner
         (GeneratedContextControlSelectionAuditForSpace &self AdaptiveFlightControl))))
!(println!
   (before-margin
      (ContextControlSelectionAuditMargin
         (GeneratedContextControlSelectionAuditForSpace &self AdaptiveFlightControl))))

; Revision as inference control (sections 11, 14.3): after the new evidence
; arrives, the regenerated context isolates the crosswind/fragile case and flips
; the selected branch.
(= (AdaptiveControlShiftAfterEvidence)
   (let* (($before
            (GeneratedContextControlSelectionAuditForSpace
               &self
               AdaptiveFlightControl))
          ($_flight-evidence
            (add-atom &self
               (ContextControlEvidence
                  AdaptiveFlightControl
                  adaptive-default-flight
                  (Fly adaptive-micro)
                  (EC 0.0 80.0)
                  ((type AdaptiveMicroDrone)
                   (weather adaptive-crosswind)
                   (payload adaptive-fragile))
                  adaptive-crosswind-fragile-flight-incident)))
          ($_grounding-evidence
            (add-atom &self
               (ContextControlEvidence
                  AdaptiveFlightControl
                  adaptive-grounding
                  (Ground adaptive-micro)
                  (EC 40.0 0.0)
                  ((type AdaptiveMicroDrone)
                   (weather adaptive-crosswind)
                   (payload adaptive-fragile))
                  adaptive-crosswind-fragile-grounding-success)))
          ($after
            (GeneratedContextControlSelectionAuditForSpace
               &self
               AdaptiveFlightControl))
          ($shift (BuildContextControlSelectionShift $before $after)))
      (BuildContextControlSelectionShiftSummary $shift)))

!(println! (adaptive-shift (AdaptiveControlShiftAfterEvidence)))

!(println!
   (after-audit
      (GeneratedContextControlSelectionAuditForSpace &self AdaptiveFlightControl)))
!(println!
   (after-margin
      (ContextControlSelectionAuditMargin
         (GeneratedContextControlSelectionAuditForSpace &self AdaptiveFlightControl))))
!(println!
   (after-result
      (GeneratedContextControlPeTTaChainerResultForSpace &self AdaptiveFlightControl)))
!(println!
   (after-proof-branch
      (ContextControlledProofSelectedBranch
         (ContextControlledResultProof
            (GeneratedContextControlPeTTaChainerResultForSpace
               &self
               AdaptiveFlightControl)))))
