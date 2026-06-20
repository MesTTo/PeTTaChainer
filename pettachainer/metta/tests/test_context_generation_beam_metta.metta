; Head-to-head tests for the pure-MeTTa beam (ContextBeamForQueryMeTTa).
;
; Each test runs both the Prolog beam (context_beam_for_query) and the pure-MeTTa
; beam on the same fixtures and asserts they select the same guard, side, and
; evidence. The fixtures are the exact packets from test_context_generation_beam.metta:
; the depth-4 needle (BeamQuad...) and the simple depth-3 case (BeamTriple...).

!(import! &self context/context_generation_beam)
!(import! &self context/context_generation_beam_metta)

; ----- fixtures (verbatim from test_context_generation_beam.metta) -----

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

(= (BeamTripleGuard)
   (ContextAnd (type MicroDrone) (ContextAnd (weather crosswind) (payload fragile))))

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

; ===== (a) depth-4 needle =====

; The MeTTa beam selects the full depth-4 conjunction, same as the Prolog beam.
!(test
   (let (ContextBeamAnswer
           $_statement $guard $side $evidence $_projection $_support $_trace $_beam)
      (ContextBeamForQueryMeTTa
         (Fly quad-micro-crosswind-fragile-rooftop)
         (BeamQuadFlyPackets)
         (BeamQuadQueryFeatures)
         4
         5)
      (BeamRoute $guard $side $evidence))
   (BeamRoute (BeamQuadGuard) inside (EC 0.0 300.0)))

; Head-to-head: Prolog and MeTTa beams agree on guard, side, and evidence.
!(test
   (let* (((ContextBeamAnswer
              $_ps $pl-guard $pl-side $pl-evidence $_pp $_psu $_pt $_pb)
             (context_beam_for_query
                (Fly quad-micro-crosswind-fragile-rooftop)
                (BeamQuadFlyPackets) (BeamQuadQueryFeatures) 4 5))
          ((ContextBeamAnswer
              $_ms $mt-guard $mt-side $mt-evidence $_mp $_msu $_mt $_mb)
             (ContextBeamForQueryMeTTa
                (Fly quad-micro-crosswind-fragile-rooftop)
                (BeamQuadFlyPackets) (BeamQuadQueryFeatures) 4 5)))
      (and
         (and (== $pl-guard $mt-guard) (== $pl-side $mt-side))
         (== $pl-evidence $mt-evidence)))
   true)

; ===== (b) simple depth-3 case =====

; The MeTTa beam selects the depth-3 conjunction, same route as the Prolog beam.
!(test
   (let (ContextBeamAnswer
           $_statement $guard $side $evidence $_projection $_support $_trace $_beam)
      (ContextBeamForQueryMeTTa
         (Fly micro-crosswind-fragile)
         (BeamTripleFlyPackets)
         (BeamTripleQueryFeatures)
         3
         5)
      (BeamRoute $guard $side $evidence))
   (BeamRoute (BeamTripleGuard) inside (EC 0.0 300.0)))

; Head-to-head on the simple case.
!(test
   (let* (((ContextBeamAnswer
              $_ps $pl-guard $pl-side $pl-evidence $_pp $_psu $_pt $_pb)
             (context_beam_for_query
                (Fly micro-crosswind-fragile)
                (BeamTripleFlyPackets) (BeamTripleQueryFeatures) 3 5))
          ((ContextBeamAnswer
              $_ms $mt-guard $mt-side $mt-evidence $_mp $_msu $_mt $_mb)
             (ContextBeamForQueryMeTTa
                (Fly micro-crosswind-fragile)
                (BeamTripleFlyPackets) (BeamTripleQueryFeatures) 3 5)))
      (and
         (and (== $pl-guard $mt-guard) (== $pl-side $mt-side))
         (== $pl-evidence $mt-evidence)))
   true)

; The projection matches the Prolog beam's STV (strength ~0.0063, confidence ~0.993).
!(test
   (let (ContextBeamAnswer
           $_statement $_guard $_side $_evidence (STV $strength $confidence) $_support $_trace $_beam)
      (ContextBeamForQueryMeTTa
         (Fly micro-crosswind-fragile)
         (BeamTripleFlyPackets)
         (BeamTripleQueryFeatures)
         3
         5)
      (and
         (and (> $strength 0.006) (< $strength 0.007))
         (and (> $confidence 0.993) (< $confidence 0.994))))
   true)

; The support is the single conflicting incident packet, same as the Prolog beam.
!(test
   (let (ContextBeamAnswer
           $_statement $_guard $_side $_evidence $_projection $support $_trace $_beam)
      (ContextBeamForQueryMeTTa
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

; The trace carries the same conflict reduction (~0.4) and score (~1.01).
!(test
   (let (ContextBeamAnswer
           $_statement $_guard $_side $_evidence $_projection $_support
           (ContextScoreTrace
              $_trace-guard $_parent $_split $_parent-conflict $_split-conflict
              (ConflictReduction $reduction) $_focus $_penalty (Score $score))
           $_beam)
      (ContextBeamForQueryMeTTa
         (Fly micro-crosswind-fragile)
         (BeamTripleFlyPackets)
         (BeamTripleQueryFeatures)
         3
         5)
      (and
         (and (> $reduction 0.399) (< $reduction 0.401))
         (and (> $score 1.009) (< $score 1.011))))
   true)

; The beam holds the top-5 candidate reports.
!(test
   (let (ContextBeamAnswer
           $_statement $_guard $_side $_evidence $_projection $_support $_trace (Beam $reports))
      (ContextBeamForQueryMeTTa
         (Fly micro-crosswind-fragile)
         (BeamTripleFlyPackets)
         (BeamTripleQueryFeatures)
         3
         5)
      (length $reports))
   5)

; ===== degenerate cases match the Prolog fallback =====

; No packets gives the fallback answer (none / outside / empty), same as Prolog.
!(test
   (ContextBeamForQueryMeTTa (Fly nothing) () () 3 5)
   (ContextBeamAnswer
      (Fly nothing)
      none
      outside
      (EC 0.0 0.0)
      (STV 0.95 0.0)
      ()
      (ContextScoreTrace none)
      (Beam ())))

; A zero beam width also falls back, same as Prolog.
!(test
   (let (ContextBeamAnswer $_s $guard $side $_e $_p $_su $_t (Beam $reports))
      (ContextBeamForQueryMeTTa
         (Fly micro-crosswind-fragile)
         (BeamTripleFlyPackets)
         (BeamTripleQueryFeatures)
         3
         0)
      (BeamFallback $guard $side $reports))
   (BeamFallback none outside ()))
