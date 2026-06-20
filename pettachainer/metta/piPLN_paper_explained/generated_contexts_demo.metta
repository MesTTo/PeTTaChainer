; Evidence-derived context generation demo.
;
; Demos section 13.2 open context generation and the section 16.1 hard case:
; near-miss evidence where every single feature and shallow pair is misleading,
; so only a deep guard isolates the exception. The pure depth-3 enumerator cannot
; name the depth-4 needle, while the beam can.
;
; This is the missing step left implicit by chart selection: there are no
; predeclared MicroDrone, crosswind, or fragile-payload charts. The context is
; generated from packet features at query time, then scored by conflict
; reduction and projected to an STV.

!(import! &self context/context_generation_beam)

(= (TripleOnlyFlyPackets)
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

(= (TripleOnlyQueryFeatures)
   ((type MicroDrone) (weather crosswind) (payload fragile)))

(= (QuadOnlyFlyPackets)
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

(= (QuadOnlyQueryFeatures)
   ((type QuadMicroDrone) (weather quad-crosswind) (payload quad-fragile) (habitat quad-rooftop)))

(= (QuadOnlyGuard)
   (ContextAnd
      (type QuadMicroDrone)
      (ContextAnd
         (weather quad-crosswind)
         (ContextAnd (payload quad-fragile) (habitat quad-rooftop)))))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly space-micro-crosswind-normal)
      (EC 300.0 0.0)
      ((type SpaceMicroDrone) (weather space-crosswind) (payload space-normal))
      space-micro-crosswind-normal-flight))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly space-micro-calm-fragile)
      (EC 300.0 0.0)
      ((type SpaceMicroDrone) (weather space-calm) (payload space-fragile))
      space-micro-calm-fragile-flight))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly space-heavy-crosswind-fragile)
      (EC 300.0 0.0)
      ((type SpaceHeavyDrone) (weather space-crosswind) (payload space-fragile))
      space-heavy-crosswind-fragile-flight))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly space-heavy-calm-normal)
      (EC 300.0 0.0)
      ((type SpaceHeavyDrone) (weather space-calm) (payload space-normal))
      space-heavy-calm-normal-flight))

!(add-atom &self
   (ContextEvidence
      Fly
      (Fly space-micro-crosswind-fragile)
      (EC 0.0 300.0)
      ((type SpaceMicroDrone) (weather space-crosswind) (payload space-fragile))
      space-micro-crosswind-fragile-incident))

!(add-atom &self
   (ContextStatementFeatures
      Fly
      (Fly space-unseen-micro-crosswind-fragile)
      ((type SpaceMicroDrone) (weather space-crosswind) (payload space-fragile))))

(= (SpaceQueryFeatures)
   ((type SpaceMicroDrone) (weather space-crosswind) (payload space-fragile)))

; The pairwise context is still polluted: it captures one positive and one
; negative packet, so it cannot explain the exception cleanly.
!(GeneratedContextScoreTrace
   (ContextAnd (type MicroDrone) (weather crosswind))
   (TripleOnlyFlyPackets)
   (TripleOnlyQueryFeatures))

; The generated triple context isolates the exception.
!(GeneratedContextScoreTrace
   (ContextAnd (type MicroDrone) (ContextAnd (weather crosswind) (payload fragile)))
   (TripleOnlyFlyPackets)
   (TripleOnlyQueryFeatures))

; End-to-end generated answer with selected context, evidence, projected STV,
; exact support packet, and score trace.
!(GeneratedContextExplanationForQuery
   (Fly micro-crosswind-fragile)
   (TripleOnlyFlyPackets)
   (TripleOnlyQueryFeatures))

; Counterfactual ablation certificate: each atomic feature is removed from the
; generated context and rescored, so the report shows why the full context is
; not an arbitrary overfit conjunction.
!(GeneratedContextMinimalityReportForQuery
   (Fly micro-crosswind-fragile)
   (TripleOnlyFlyPackets)
   (TripleOnlyQueryFeatures))

; Same pure PeTTa result, projected into the chaining convention:
;   (: truth-value proof-tree conclusion)
!(GeneratedContextChainingTripleForQuery
   (Fly micro-crosswind-fragile)
   (TripleOnlyFlyPackets)
   (TripleOnlyQueryFeatures))

; Same result in PeTTaChainer's native query-result convention:
;   (: proof-tree statement truth-value)
!(GeneratedContextPeTTaChainerResultForQuery
   (Fly micro-crosswind-fragile)
   (TripleOnlyFlyPackets)
   (TripleOnlyQueryFeatures))

; Same query through the Prolog-backed PeTTa beam path. The last argument asks
; for the top five generated candidates among contexts up to depth three.
!(context_beam_for_query
   (Fly micro-crosswind-fragile)
   (TripleOnlyFlyPackets)
   (TripleOnlyQueryFeatures)
   3
   5)

; The section 16.1 hard case: the pure PeTTa enumerator is intentionally depth-3,
; so the exact quad guard is not in its candidate set. The Prolog beam searches to
; depth four (section 13.2) and returns a certified answer for that deeper context.
!(is-member (QuadOnlyGuard) (GeneratedContextGuards (QuadOnlyFlyPackets)))

!(ContextBeamCertifiedPeTTaChainerResultForQuery
   (Fly quad-micro-crosswind-fragile-rooftop)
   (QuadOnlyFlyPackets)
   (QuadOnlyQueryFeatures)
   4
   5)

; PeTTa atomspace style: collect ContextEvidence facts by match/collapse, then
; return the same chaining-style triple.
!(ContextQueryFeaturesFromSpace
   &self
   Fly
   (Fly space-unseen-micro-crosswind-fragile))

!(GeneratedContextChainingTripleForSpaceQuery
   &self
   Fly
   (Fly space-micro-crosswind-fragile)
   (SpaceQueryFeatures))

!(GeneratedContextPeTTaChainerResultForSpaceQuery
   &self
   Fly
   (Fly space-micro-crosswind-fragile)
   (SpaceQueryFeatures))

; Fully atomspace-driven version: infer the query features from ContextEvidence,
; then generate and score the context without a manually supplied feature list.
!(GeneratedContextPeTTaChainerResultForSpaceStatement
   &self
   Fly
   (Fly space-unseen-micro-crosswind-fragile))

!(GeneratedContextMinimalityReportForSpaceStatement
   &self
   Fly
   (Fly space-unseen-micro-crosswind-fragile))

; Single proof-carrying answer: context generation, score trace, minimality
; certificate, evidence selection, and STV projection in PeTTaChainer result
; order.
!(GeneratedContextCertifiedPeTTaChainerResultForSpaceStatement
   &self
   Fly
   (Fly space-unseen-micro-crosswind-fragile))

!(ContextBeamChainingTripleForSpaceQuery
   &self
   Fly
   (Fly space-micro-crosswind-fragile)
   (SpaceQueryFeatures)
   3
   5)

!(ContextBeamPeTTaChainerResultForSpaceQuery
   &self
   Fly
   (Fly space-micro-crosswind-fragile)
   (SpaceQueryFeatures)
   3
   5)

!(ContextBeamPeTTaChainerResultForSpaceStatement
   &self
   Fly
   (Fly space-unseen-micro-crosswind-fragile)
   3
   5)

!(ContextBeamCertifiedPeTTaChainerResultForSpaceStatement
   &self
   Fly
   (Fly space-unseen-micro-crosswind-fragile)
   3
   5)
