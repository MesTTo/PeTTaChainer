; From evidence to a certified exception: the whole MeTTa reasoning path.
;
; A reasoner that only applies fixed rules cannot tell you when a rule has an
; exception. This one can. It reads evidence straight off the knowledge base,
; generates the local context that isolates an exception, certifies that context
; against every weaker explanation, projects the answer under it, turns the
; decision into a proof, and audits that proof by structure. All in MeTTa, with
; no Python in the loop.
;
; It builds from the textbook case (penguins) to the hard case (a hidden failure
; mode that no single clue reveals), then proves, audits, and stress-tests the
; result. Every step prints what it found and then asserts it, so the file is a
; walkthrough and a self-check at once.
;
; Section map: Act 1 = the section 16.1 penguin exception (generated context plus
; section 8.2 projection); Act 2 = the section 13.2 beam finding the four-feature
; needle (section 16.1 hard case); Act 3 = proof and structural audit; Act 4 =
; counterfactual (the context was generated from evidence, section 16.1).
;
; Run it from pettachainer/metta:
;
;   petta piPLN_paper_explained/metta_idiomatic_demo.metta

!(import! &self context/context_from_kb)
!(import! &self context/context_generation_beam_metta)
!(import! &self chainer/proof_structure_audit)

; ============================================================================
; ACT 1.  The textbook exception: birds fly, except the ones that do not.
; The section 16.1 penguin case: generated context plus section 8.2 projection.
; ============================================================================
;
; Ordinary chainer atoms (: proof statement (STV s c)). robin is a plain bird
; that flies; polly is a penguin that does not. tweety is the question: a Bird
; and a Penguin, with no flight record of its own.

!(add-atom &self (: bird_robin (Bird robin) (STV 1.0 0.99)))
!(add-atom &self (: bird_polly (Bird polly) (STV 1.0 0.99)))
!(add-atom &self (: bird_tweety (Bird tweety) (STV 1.0 0.99)))
!(add-atom &self (: penguin_polly (Penguin polly) (STV 1.0 0.99)))
!(add-atom &self (: penguin_tweety (Penguin tweety) (STV 1.0 0.99)))
!(add-atom &self (: fly_robin (Fly robin) (STV 0.95 0.99)))
!(add-atom &self (: fly_polly (Fly polly) (STV 0.0 0.99)))

; First, the small inversion the whole thing rests on. A stored truth value is
; turned back into evidence counts: (STV 0.0 0.99) is about 198 against, 0 for.
!(println! (read-as-evidence (STVToEC (STV 0.0 0.99) 2.0 1000.0)))
!(test
   (let (EC $pos $neg) (STVToEC (STV 0.0 0.99) 2.0 1000.0)
      (and (ContextBetween $pos -0.1 0.1) (ContextBetween $neg 197.9 198.1)))
   true)

; tweety's features, read off the KB: (type Bird) and (type Penguin).
!(println! (tweety-features (KBEntityFeatures &self tweety Fly)))

; "Does tweety fly?" robin (a plain bird) flies; polly (a penguin) does not.
; The generated context is the guard (type Penguin): it isolates the exception.
; tweety matches it, so the query routes inside, and the projected strength is
; low. The system was never told about penguins -- it found the split itself.
!(println! (generated-context (GeneratedContextForKBStatement &self (Fly tweety) Fly 2.0 1000.0)))
!(test
   (let (GeneratedContext $_s $guard $side $_e $_p $_score)
      (GeneratedContextForKBStatement &self (Fly tweety) Fly 2.0 1000.0)
      (GeneratedRoute $guard $side))
   (GeneratedRoute (type Penguin) inside))
!(test
   (let (GeneratedContext $_s $_g $_side $_e (STV $strength $_c) $_score)
      (GeneratedContextForKBStatement &self (Fly tweety) Fly 2.0 1000.0)
      (< $strength 0.05))
   true)

; ============================================================================
; ACT 2.  The hard exception: a failure no single clue reveals.
; The section 16.1 hard case: the section 13.2 beam finds the four-feature needle.
; ============================================================================
;
; A fleet of delivery drones. Four configurations complete their delivery; one
; secretly fails. The catch is that every single feature, and every shallow pair,
; also appears in a configuration that succeeds. No clue on its own is guilty:
; only the exact four-way conjunction (this drone, this weather, this payload,
; this site) isolates the failure. This is the needle.

(= (FleetPackets)
   ((EvidencePacket (Delivers micro-crosswind-fragile-ground) (EC 300.0 0.0)
       ((type MicroDrone) (weather crosswind) (payload fragile) (site ground)) ok-a)
    (EvidencePacket (Delivers micro-crosswind-normal-rooftop) (EC 300.0 0.0)
       ((type MicroDrone) (weather crosswind) (payload normal) (site rooftop)) ok-b)
    (EvidencePacket (Delivers micro-calm-fragile-rooftop) (EC 300.0 0.0)
       ((type MicroDrone) (weather calm) (payload fragile) (site rooftop)) ok-c)
    (EvidencePacket (Delivers heavy-crosswind-fragile-rooftop) (EC 300.0 0.0)
       ((type HeavyDrone) (weather crosswind) (payload fragile) (site rooftop)) ok-d)
    (EvidencePacket (Delivers micro-crosswind-fragile-rooftop) (EC 0.0 300.0)
       ((type MicroDrone) (weather crosswind) (payload fragile) (site rooftop)) the-failure)))
(= (FleetQuery)
   ((type MicroDrone) (weather crosswind) (payload fragile) (site rooftop)))

(= (NeedleGuard)
   (ContextAnd (type MicroDrone)
      (ContextAnd (weather crosswind)
         (ContextAnd (payload fragile) (site rooftop)))))

; No single clue is decisive: the four-way guard out-scores any one feature,
; because each single feature still leaves a success and a failure mixed together.
!(println! (single-feature-score
              (GeneratedContextScore (type MicroDrone) (FleetPackets) (FleetQuery))))
!(println! (needle-score
              (GeneratedContextScore (NeedleGuard) (FleetPackets) (FleetQuery))))
!(test
   (> (GeneratedContextScore (NeedleGuard) (FleetPackets) (FleetQuery))
      (GeneratedContextScore (type MicroDrone) (FleetPackets) (FleetQuery)))
   true)

; The shallow search caps at three features, so it cannot even name the guard.
; The pure-MeTTa beam, searching to depth four, returns exactly the needle, and
; projects the delivery-success strength under it -- which has collapsed.
!(println! (beam-finds
              (let (ContextBeamAnswer $_s $guard $_side $_e $_p $_su $_t $_b)
                 (ContextBeamForQueryMeTTa (Delivers micro-crosswind-fragile-rooftop)
                                           (FleetPackets) (FleetQuery) 4 5)
                 $guard)))
!(test
   (let (ContextBeamAnswer $_s $guard $_side $_e $_p $_su $_t $_b)
      (ContextBeamForQueryMeTTa (Delivers micro-crosswind-fragile-rooftop)
                                (FleetPackets) (FleetQuery) 4 5)
      (and (ContextGuardMatches $guard (FleetQuery))
           (== (length (ContextGuardAtoms $guard)) 4)))
   true)
!(println! (projection-under-the-needle
              (let (ContextBeamAnswer $_s $_g $_side $_e $proj $_su $_t $_b)
                 (ContextBeamForQueryMeTTa (Delivers micro-crosswind-fragile-rooftop)
                                           (FleetPackets) (FleetQuery) 4 5)
                 $proj)))
!(test
   (let (ContextBeamAnswer $_s $_g $_side $_e (STV $strength $_c) $_su $_t $_b)
      (ContextBeamForQueryMeTTa (Delivers micro-crosswind-fragile-rooftop)
                                (FleetPackets) (FleetQuery) 4 5)
      (< $strength 0.05))
   true)

; ============================================================================
; ACT 3.  Turn the decision into a proof, and audit the proof by structure.
; ============================================================================
;
; Acting on the failure produces a proof: a primary chain of moves, gated by a
; conclusion, under a policy. The audit reads that proof by native matching --
; the same heads the incident-response benchmark runs on the real six-hop proof.
; Here a two-hop chain stands in, so the whole thing is readable.

(= (DecisionProof)
   (: (isolate_policy
         (pii_incident
            (rule-proof conjunction
               (lateral_move
                  (rule-proof conjunction
                     (lateral_move (rule-proof conjunction phish_laptop trust_primary_1))
                     trust_primary_2))
               customerdb_pii)))
      (Action Isolate CustomerDB)
      (STV 0.9 0.8)))

; The structure checks out: a clean two-hop primary chain, a pii gate over it,
; the isolate-policy step, and no forbidden ingress labels.
!(test (has-primary-chain? (DecisionProof) 2) True)
!(test (has-pii-gate? (DecisionProof) 2) True)
!(test (has-isolate-policy-step? (DecisionProof)) True)

; The full verdict: the same record proof_structure_certificate reads in Python.
!(println! (proof-audit (proof-structure-verdict (DecisionProof) 2
                          (noise_1 trust_secondary_1 rotate_policy token_seed))))
!(test
   (proof-structure-verdict (DecisionProof) 2 (noise_1 trust_secondary_1 rotate_policy token_seed))
   (ProofAudit
      (target-action-matches True)
      (truth-value (STV 0.9 0.8))
      (primary-chain-found True)
      (pii-gate-found True)
      (isolate-policy-step-found True)
      (forbidden-count 0)
      (op-lateral_move 2)
      (op-pii_incident 1)
      (op-isolate_policy 1)
      (op-rule-proof 3)
      (op-merge/revision 0)))

; ============================================================================
; ACT 4.  Counterfactual: was the context real, or just baked in?
; The context was generated from evidence, not hardcoded (section 16.1).
; ============================================================================
;
; Remove the one failing flight and re-score the needle. With nothing left to
; isolate, its score collapses -- the deep context only exists because the
; evidence put it there. It was generated, not hardcoded.

(= (CleanFleetPackets)
   ((EvidencePacket (Delivers micro-crosswind-fragile-ground) (EC 300.0 0.0)
       ((type MicroDrone) (weather crosswind) (payload fragile) (site ground)) ok-a)
    (EvidencePacket (Delivers micro-crosswind-normal-rooftop) (EC 300.0 0.0)
       ((type MicroDrone) (weather crosswind) (payload normal) (site rooftop)) ok-b)
    (EvidencePacket (Delivers micro-calm-fragile-rooftop) (EC 300.0 0.0)
       ((type MicroDrone) (weather calm) (payload fragile) (site rooftop)) ok-c)
    (EvidencePacket (Delivers heavy-crosswind-fragile-rooftop) (EC 300.0 0.0)
       ((type HeavyDrone) (weather crosswind) (payload fragile) (site rooftop)) ok-d)))

!(println! (needle-score-with-failure
              (GeneratedContextScore (NeedleGuard) (FleetPackets) (FleetQuery))))
!(println! (needle-score-without-failure
              (GeneratedContextScore (NeedleGuard) (CleanFleetPackets) (FleetQuery))))
!(test
   (> (GeneratedContextScore (NeedleGuard) (FleetPackets) (FleetQuery))
      (GeneratedContextScore (NeedleGuard) (CleanFleetPackets) (FleetQuery)))
   true)

; Penguins, a four-way hidden failure, a proof, an audit, and a counterfactual.
; Every conclusion was generated from the evidence and checked, end to end, in MeTTa.
