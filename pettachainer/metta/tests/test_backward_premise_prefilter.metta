!(import! &self petta_chainer)

(= (prefilter-test-row $kb $type) ($type ($kb MAIN Nil) $proof $tv))

(= (prefilter-side-effect)
   (progn (change-state! prefilter_side_effect_fired true) true))

(= (prefilter-materialize-later-fact)
   (progn
      (add-atom &kb
         ((EffectLater) (prefilterTestKb MAIN Nil) effectLaterProof (STV 1.0 1.0)))
      true))

(= (prefilter-side-effect-fired?)
   (let $value (catch (get-state prefilter_side_effect_fired))
      (if-error $value false $value)))

!(set-backward-premise-prefilter prefilterTestKb true)

!(test
   (rule-premise-prefilter-prunes?
      (prefilter-test-row prefilterTestKb (MissingTarget))
      ((prefilter-test-row prefilterTestKb (MissingSource))))
   true)

!(add-to-kb
   ((PresentSource) (prefilterTestKb MAIN Nil) presentSourceProof (STV 1.0 1.0)))

!(test
   (rule-premise-prefilter-prunes?
      (prefilter-test-row prefilterTestKb (PresentTarget))
      ((prefilter-test-row prefilterTestKb (PresentSource))))
   false)

!(test
   (rule-premise-prefilter-prunes?
      (prefilter-test-row prefilterTestKb (PresentThenMissingTarget))
      ((prefilter-test-row prefilterTestKb (PresentSource))
       (prefilter-test-row prefilterTestKb (MissingAfterDirectFact))))
   true)

!(kb-add-expr live
   (rules
      ((((DerivableBase) (prefilterTestKb MAIN Nil) derivableBaseProof (STV 1.0 1.0)))
       |-
       ((DerivableSource) (prefilterTestKb MAIN Nil) derivableRuleProof (STV 1.0 1.0)))))

!(test
   (rule-premise-prefilter-prunes?
      (prefilter-test-row prefilterTestKb (DerivableTarget))
      ((prefilter-test-row prefilterTestKb (DerivableSource))
       (prefilter-test-row prefilterTestKb (MissingAfterDerivable))))
   false)

!(add-to-kb
   ((WildcardSource #) (prefilterTestKb SPECIAL Nil) wildcardSourceProof (STV 1.0 1.0)))

!(test
   (rule-premise-prefilter-prunes?
      ((WildcardTarget) (prefilterTestKb SPECIAL Nil) $proof $tv)
      (((WildcardSource value) (prefilterTestKb SPECIAL Nil) $source-proof $source-tv)))
   false)

!(change-state! prefilter_side_effect_fired false)

!(test
   (let $pruned
      (rule-premise-prefilter-prunes?
         (prefilter-test-row prefilterTestKb (EffectTarget))
         ((CPU prefilter-side-effect () $result)
          (prefilter-test-row prefilterTestKb (EffectMissing))))
      ($pruned (prefilter-side-effect-fired?)))
   (false false))

!(kb-add-expr live
   (rules
      (((CPU prefilter-materialize-later-fact () true))
        |-
        ((EffectSource) (prefilterTestKb MAIN Nil) effectSourceRule (STV 1.0 1.0)))))

!(kb-add-expr live
   (rules
      ((((EffectSource) (prefilterTestKb MAIN Nil) $source-proof $source-tv)
        ((EffectLater) (prefilterTestKb MAIN Nil) $later-proof $later-tv))
       |-
       ((EffectTarget) (prefilterTestKb MAIN Nil) effectTargetRule (STV 1.0 1.0)))))

!(test
   (let*
      (($_off (set-backward-premise-prefilter prefilterTestKb false))
       ($without (collapse (query 20 prefilterTestKb (: $proof (EffectTarget) $tv))))
       ($_reset
          (remove-atom &kb
             ((EffectLater) (prefilterTestKb MAIN Nil) effectLaterProof (STV 1.0 1.0))))
       ($_on (set-backward-premise-prefilter prefilterTestKb true))
       ($with (collapse (query 20 prefilterTestKb (: $proof (EffectTarget) $tv)))))
      ((not (== $without ())) (not (== $with ()))))
   (true true))

!(test
   (rule-premise-prefilter-prunes?
      (prefilter-test-row prefilterTestKb (OpenTarget))
      (((OpenSource $value) (prefilterTestKb MAIN Nil) $source-proof $source-tv)))
   false)

!(set-backward-premise-prefilter prefilterTestKb false)

!(test
   (rule-premise-prefilter-prunes?
      (prefilter-test-row prefilterTestKb (DisabledTarget))
      ((prefilter-test-row prefilterTestKb (DisabledMissing))))
   false)

!(test
   ((backward-premise-prefilter?
       (prefilter-test-row prefilterTestKb (DisabledTarget)))
    (backward-premise-prefilter?
       (prefilter-test-row otherPrefilterTestKb (OtherTarget))))
   (false false))

!(compileadd prefilterQueryKb
   (: liveSource (FilterSource live) (STV 1.0 1.0)))

!(compileadd prefilterQueryKb
   (: liveRule
      (Implication (Premises (FilterSource live)) (Conclusions (FilterTarget)))
      (STV 1.0 0.2)))

!(compileadd prefilterQueryKb
   (: (no_inverse deadRuleOne)
      (Implication (Premises (FilterSource dead-one)) (Conclusions (FilterTarget)))
      (STV 1.0 1.0)))

!(compileadd prefilterQueryKb
   (: (no_inverse deadRuleTwo)
      (Implication (Premises (FilterSource dead-two)) (Conclusions (FilterTarget)))
      (STV 1.0 0.9)))

!(compileadd prefilterQueryKb
   (: (no_inverse deadRuleThree)
      (Implication (Premises (FilterSource dead-three)) (Conclusions (FilterTarget)))
      (STV 1.0 0.8)))

!(compileadd prefilterQueryKb
   (: (no_inverse deadRuleFour)
      (Implication (Premises (FilterSource dead-four)) (Conclusions (FilterTarget)))
      (STV 1.0 0.7)))

!(compileadd prefilterQueryKb
   (: (no_inverse deadRuleFive)
      (Implication (Premises (FilterSource dead-five)) (Conclusions (FilterTarget)))
      (STV 1.0 0.6)))

!(compileadd prefilterQueryKb
   (: (no_inverse deadRuleSix)
      (Implication (Premises (FilterSource dead-six)) (Conclusions (FilterTarget)))
      (STV 1.0 0.5)))

!(test
   (let*
      (($_off (set-backward-premise-prefilter prefilterQueryKb false))
       ($without (collapse (query 100 prefilterQueryKb (: $proof (FilterTarget) $tv))))
       ($_on (set-backward-premise-prefilter prefilterQueryKb true))
       ($with (collapse (query 100 prefilterQueryKb (: $proof (FilterTarget) $tv)))))
      (== (list_to_set $with) (list_to_set $without)))
   true)

!(test
   (let*
      (($_off (set-backward-premise-prefilter prefilterQueryKb false))
       ($without (collapse (query 4 prefilterQueryKb (: $proof (FilterTarget) $tv))))
       ($_on (set-backward-premise-prefilter prefilterQueryKb true))
       ($with (collapse (query 4 prefilterQueryKb (: $proof (FilterTarget) $tv)))))
      ((== $without ()) (not (== $with ()))))
   (true true))
