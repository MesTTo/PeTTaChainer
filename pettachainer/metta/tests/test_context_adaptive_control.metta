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

; Baseline evidence: micro drones usually fly, and grounding is usually not
; needed in the broad type-level context.
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

!(test
   (length
      (collapse
         (match &self
            (ContextControlCandidate AdaptiveFlightControl $name $statement $action)
            $name)))
   2)

!(test
   (length (ContextControlCandidatesFromSpace &self AdaptiveFlightControl))
   2)

!(test
   (length (ContextControlBranchesFromSpace &self AdaptiveFlightControl))
   2)

!(test
   (length
      (ContextControlResultReports
         (GeneratedContextControlForSpace &self AdaptiveFlightControl)))
   2)

!(test
   (ContextControlSelectionAuditWinner
      (GeneratedContextControlSelectionAuditForSpace &self AdaptiveFlightControl))
   adaptive-default-flight)

!(test
   (ContextBranchReportName
      (ContextControlSelectionAuditRunnerUp
         (GeneratedContextControlSelectionAuditForSpace &self AdaptiveFlightControl)))
   adaptive-grounding)

; New incident evidence arrives in the same atomspace. No caller supplies a
; predeclared exception context; it must be regenerated from the new features.
!(test
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
      (and
         (== (ContextControlSelectionShiftChanged $shift) True)
         (and
            (== (ContextControlSelectionShiftPreviousWinner $shift)
                adaptive-default-flight)
            (and
               (== (ContextControlSelectionShiftNewWinner $shift)
                   adaptive-grounding)
               (== (ContextControlSelectionShiftNewGuard $shift)
                   (payload adaptive-fragile))))))
   True)

!(test
   (let* (($before
            (ContextControlSelectionAudit
               adaptive-default-flight
               (try-adaptive-default-flight)
               (ContextBranchReport
                  adaptive-default-flight
                  (Fly adaptive-micro)
                  (try-adaptive-default-flight)
                  (type AdaptiveMicroDrone)
                  inside
                  (EC 50.0 0.0)
                  (STV 0.99 0.9)
                  1.0
                  0.25
                  ()
                  trace
                  minimality)
               0.25
               NoContextBranchReport
               0.0
               0.25
               ()))
          ($after
            (ContextControlSelectionAudit
               adaptive-grounding
               (use-adaptive-grounding-rule)
               (ContextBranchReport
                  adaptive-grounding
                  (Ground adaptive-micro)
                  (use-adaptive-grounding-rule)
                  (payload adaptive-fragile)
                  inside
                  (EC 40.0 0.0)
                  (STV 0.99 0.95)
                  1.4
                  1.09
                  ()
                  trace
                  minimality)
               1.09
               NoContextBranchReport
               0.0
               1.09
               ()))
          ($shift (BuildContextControlSelectionShift $before $after)))
      (BuildContextControlSelectionShiftSummary $shift))
   (ContextControlSelectionShiftSummary
      adaptive-default-flight
      adaptive-grounding
      (type AdaptiveMicroDrone)
      (payload adaptive-fragile)
      1.09
      True))

!(test
   (ContextControlSelectionAuditWinner
      (GeneratedContextControlSelectionAuditForSpace &self AdaptiveFlightControl))
   adaptive-grounding)

!(test
   (ContextBranchReportName
      (ContextControlSelectionAuditRunnerUp
         (GeneratedContextControlSelectionAuditForSpace &self AdaptiveFlightControl)))
   adaptive-default-flight)

!(test
   (ContextControlledResultStatement
      (GeneratedContextControlPeTTaChainerResultForSpace &self AdaptiveFlightControl))
   (Ground adaptive-micro))

!(test
   (ContextControlledProofSelectedBranch
      (ContextControlledResultProof
         (GeneratedContextControlPeTTaChainerResultForSpace &self AdaptiveFlightControl)))
   adaptive-grounding)

!(test
   (ContextControlSelectionAuditWinner
      (ContextControlledProofSelectionAudit
         (ContextControlledResultProof
            (GeneratedContextControlPeTTaChainerResultForSpace &self AdaptiveFlightControl))))
   adaptive-grounding)

!(test
   (ContextBetween
      (ContextControlSelectionAuditMargin
         (GeneratedContextControlSelectionAuditForSpace &self AdaptiveFlightControl))
      0.91
      0.92)
   True)
