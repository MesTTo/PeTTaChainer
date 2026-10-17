!(import! &self petta_chainer)

(= (SpecializationSymmetryRule $name $tv)
   (: $name
      (Implication
         (Premises (Symmetric $relation) ($relation $left $right))
         (Conclusions ($relation $right $left)))
      $tv))

!(set-specializing-predicate Symmetric)
!(set-specializing-predicate Symmetric)

!(test
   (let $_ignored (set-specializing-predicate $predicate)
      (specializing-predicate? UnregisteredPredicate))
   false)

; Registration is idempotent.
!(test
   (length
      (collapse
         (match &logic_config (specializing-predicate Symmetric) true)))
   1)

; A structural rule added before its trigger fact remains a template until the
; relation variable can be grounded.
!(compileadd specializationRuleFirstKb
   (SpecializationSymmetryRule symmetricRule (STV 0.9 0.9)))

!(test
   (length
      (collapse
         (match &ccls_head_index
            ((fwd_trigger specializationRuleFirstKb any) $id)
            $id)))
   0)

!(compileadd specializationRuleFirstKb
   (: symmetricFriend (Symmetric Friend) (STV 0.9 0.9)))
!(compileadd specializationRuleFirstKb
   (: friendBobAlice (Friend bob alice) (STV 0.9 0.9)))

!(test
   (query 100 specializationRuleFirstKb
      (: $proof (Friend alice bob) $tv))
   (: (rule-proof symmetricRule
         (rule-proof conjunction symmetricFriend friendBobAlice))
      (Friend alice bob)
      (STV 0.7670000000000001 0.7670000000000001)))

!(test
   (query 100 specializationRuleFirstKb
      (: $proof (Friend alice $who) $tv))
   (: (rule-proof symmetricRule
         (rule-proof conjunction symmetricFriend friendBobAlice))
      (Friend alice bob)
      (STV 0.7670000000000001 0.7670000000000001)))

; Specialization retains the trigger as an ordinary premise and stores its fact.
!(test
   (collapse
      (match &kb
         ((Symmetric $relation)
            (specializationRuleFirstKb MAIN Nil)
            $proof
            $tv)
         ($relation $proof $tv)))
   ((Friend symmetricFriend (STV 0.9 0.9))))

!(test
   (length
      (collapse
         (match &ccls_head_index
            ((fwd_trigger specializationRuleFirstKb Friend) $id)
            $id)))
   1)

; Re-adding the exact template must not duplicate its grounded rule.
!(compileadd specializationRuleFirstKb
   (SpecializationSymmetryRule symmetricRule (STV 0.9 0.9)))

!(test
   (length
      (collapse
         (match &ccls_head_index
            ((fwd_trigger specializationRuleFirstKb Friend) $id)
            $id)))
   1)

; Facts can arrive before the structural rule.
!(compileadd specializationFactFirstKb
   (: symmetricSibling (Symmetric Sibling) (STV 1.0 1.0)))
!(compileadd specializationFactFirstKb
   (: siblingBobAlice (Sibling bob alice) (STV 1.0 1.0)))
!(compileadd specializationFactFirstKb
   (SpecializationSymmetryRule siblingSymmetry (STV 1.0 1.0)))

!(test
   (query 100 specializationFactFirstKb
      (: $proof (Sibling alice bob) $tv))
   (: (rule-proof siblingSymmetry
         (rule-proof conjunction symmetricSibling siblingBobAlice))
      (Sibling alice bob)
      (STV 1.0 1.0)))

; Distinct statements with the same grounded type are distinct rules. The
; statement identity includes the proof name and truth value.
!(compileadd specializationDistinctKb
   (: distinctSymmetricFriend (Symmetric Friend) (STV 1.0 1.0)))
!(compileadd specializationDistinctKb
   (SpecializationSymmetryRule distinctRuleA (STV 0.9 0.9)))
!(compileadd specializationDistinctKb
   (SpecializationSymmetryRule distinctRuleB (STV 0.8 0.7)))

!(test
   (let $names
      (collapse
         (match &rules
            ($id
               ((Friend $right $left)
                  (specializationDistinctKb $ctx $vars)
                  ($name $premise-proof)
                  $tv)
               $premises)
            $name))
      ((length $names)
       (is-member distinctRuleA $names)
       (is-member distinctRuleB $names)))
   (2 true true))

; When two trigger premises have the same head, a new fact may ground either
; occurrence. Grounding only the first occurrence loses valid rule instances.
!(set-specializing-predicate RelationRole)
!(compileadd specializationRepeatedTriggerKb
   (: composeRelations
      (Implication
         (Premises
            (RelationRole $first)
            (RelationRole $second)
            ($first $x $middle)
            ($second $middle $z))
         (Conclusions ($first $x $z)))
      (STV 1.0 1.0)))
!(compileadd specializationRepeatedTriggerKb
   (: friendRole (RelationRole Friend) (STV 1.0 1.0)))
!(compileadd specializationRepeatedTriggerKb
   (: siblingRole (RelationRole Sibling) (STV 1.0 1.0)))
!(compileadd specializationRepeatedTriggerKb
   (: friendAB (Friend a b) (STV 1.0 1.0)))
!(compileadd specializationRepeatedTriggerKb
   (: siblingBC (Sibling b c) (STV 1.0 1.0)))

!(test
   (query 150 specializationRepeatedTriggerKb
      (: $proof (Friend a c) $tv))
   (: (rule-proof composeRelations
         (rule-proof conjunction friendRole siblingRole friendAB siblingBC))
      (Friend a c)
      (STV 1.0 1.0)))
