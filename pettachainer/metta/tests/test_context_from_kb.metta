!(import! &self context/context_from_kb)

; --- Task 1: STVToEC (inverse of ContextECToSTV) ---
; total = min(cap, prior * c/(1-c)); pos = s*total, neg = (1-s)*total. Float math, so band-check.
!(test
   (let (EC $pos $neg) (STVToEC (STV 1.0 0.99) 2.0 1000.0)
      (and (ContextBetween $pos 197.9 198.1) (ContextBetween $neg -0.1 0.1)))
   true)
!(test
   (let (EC $pos $neg) (STVToEC (STV 0.0 0.99) 2.0 1000.0)
      (and (ContextBetween $pos -0.1 0.1) (ContextBetween $neg 197.9 198.1)))
   true)
!(test
   (let (EC $pos $neg) (STVToEC (STV 0.95 0.99) 2.0 1000.0)
      (and (ContextBetween $pos 188.0 188.2) (ContextBetween $neg 9.8 10.0)))
   true)
; confidence >= 1 saturates to the cap
!(test
   (let (EC $pos $neg) (STVToEC (STV 1.0 1.0) 2.0 1000.0)
      (and (ContextBetween $pos 999.9 1000.1) (ContextBetween $neg -0.1 0.1)))
   true)
; confidence <= 0 yields no evidence
!(test
   (let (EC $pos $neg) (STVToEC (STV 0.5 0.0) 2.0 1000.0)
      (and (ContextBetween $pos -0.1 0.1) (ContextBetween $neg -0.1 0.1)))
   true)

; --- Task 2: KBEntityFeatures (feature atoms derived from stored atoms) ---
; A small KB. tweety has no (Fly tweety) atom (it is the query target).
!(add-atom &self (: bird_robin (Bird robin) (STV 1.0 0.99)))
!(add-atom &self (: bird_polly (Bird polly) (STV 1.0 0.99)))
!(add-atom &self (: bird_tweety (Bird tweety) (STV 1.0 0.99)))
!(add-atom &self (: penguin_polly (Penguin polly) (STV 1.0 0.99)))
!(add-atom &self (: penguin_tweety (Penguin tweety) (STV 1.0 0.99)))
!(add-atom &self (: nests_tweety (Nests tweety cliff) (STV 1.0 0.99)))
!(add-atom &self (: migrates_tweety (Migrates tweety yes) (STV 1.0 0.30)))
!(add-atom &self (: fly_robin (Fly robin) (STV 0.95 0.99)))
!(add-atom &self (: fly_polly (Fly polly) (STV 0.0 0.99)))

!(test (length (KBEntityFeatures &self tweety Fly)) 4)
!(test (is-member (type Bird) (KBEntityFeatures &self tweety Fly)) true)
!(test (is-member (type Penguin) (KBEntityFeatures &self tweety Fly)) true)
!(test (is-member (Nests cliff) (KBEntityFeatures &self tweety Fly)) true)
!(test (is-member (Migrates yes) (KBEntityFeatures &self tweety Fly)) true)
!(test (is-member (type Penguin) (KBEntityFeatures &self robin Fly)) false)

; --- Task 3: KBStatementFeatures (union entity features over a statement's args) ---
!(test (length (KBStatementFeatures &self (Fly tweety) Fly)) 4)
!(test (is-member (type Penguin) (KBStatementFeatures &self (Fly tweety) Fly)) true)
!(test (is-member (type Penguin) (KBStatementFeatures &self (Fly robin) Fly)) false)

; --- Task 4: ContextEvidencePacketsFromKB ---
; robin and polly have (Fly _) atoms; tweety does not, so two packets.
!(test (length (ContextEvidencePacketsFromKB &self Fly 2.0 1000.0)) 2)
; total evidence: robin (~188.1, ~9.9) + polly (~0, ~198) = (~188.1, ~207.9)
!(test
   (let (EC $pos $neg) (ContextAllEvidence (ContextEvidencePacketsFromKB &self Fly 2.0 1000.0))
      (and (ContextBetween $pos 188.0 188.2) (ContextBetween $neg 207.8 208.1)))
   true)

; --- Task 5: GeneratedContext result heads from the KB (penguin scenario) ---
; (Fly tweety): the exception guard (type Penguin) should win, route inside, low strength.
!(test
   (let (GeneratedContext $_statement $guard $side $_evidence $_projection $_score)
      (GeneratedContextForKBStatement &self (Fly tweety) Fly 2.0 1000.0)
      (GeneratedRoute $guard $side))
   (GeneratedRoute (type Penguin) inside))

!(test
   (let (STV $strength $confidence)
      (ContextPeTTaChainerResultProjection
         (GeneratedContextPeTTaChainerResultForKBStatement &self (Fly tweety) Fly))
      (and (< $strength 0.05) (> $confidence 0.90)))
   true)

!(test
   (ContextPeTTaChainerResultStatement
      (GeneratedContextPeTTaChainerResultForKBStatement &self (Fly tweety) Fly))
   (Fly tweety))

; --- Phase 1b: project a query atom through generated context ---
!(test
   (let (: (generated-context) $stmt (STV $strength $_c))
      (ContextProjectionAtomForQuery &self (: $prf (Fly tweety) $tv) 2.0 1000.0)
      (and (== $stmt (Fly tweety)) (< $strength 0.05)))
   true)

; --- GeneratedContextTop2Guards (showcase scenario): penguin best, bird runner-up ---
(= (Top2Packets)
   ((EvidencePacket (Fly x) (EC 950.0 50.0)
       ((habitat temperate) (source aviary) (taxon ordinary-bird) (type Bird)) temperate-aviary)
    (EvidencePacket (Fly x) (EC 0.0 100.0)
       ((source antarctic-study) (type Bird) (type Penguin)) antarctic-study)
    (EvidencePacket (Fly x) (EC 50.0 450.0)
       ((habitat urban) (source urban-survey) (type Bird)) urban-survey)))
(= (Top2QFeat) ((source zoo-record) (type Bird) (type Penguin)))

!(test
   (let (ScoredGuard $g $_s) (RankedPairBest (GeneratedContextTop2Guards (Top2Packets) (Top2QFeat)))
      (== $g (type Penguin)))
   true)
!(test
   (let (ScoredGuard $_g $s) (RankedPairBest (GeneratedContextTop2Guards (Top2Packets) (Top2QFeat)))
      (ContextBetween $s 0.90 0.91))
   true)
!(test
   (let (ScoredGuard $g $_s) (RankedPairRunner (GeneratedContextTop2Guards (Top2Packets) (Top2QFeat)))
      (== $g (type Bird)))
   true)
!(test
   (ContextBetween (RankedPairMargin (GeneratedContextTop2Guards (Top2Packets) (Top2QFeat))) 0.124 0.126)
   true)
