!(import! &self petta_chainer)

!(test (assumption-proof? (ctx proof 4)) true)

!(test (assumption-proof? (ctx proof 4 2)) true)

!(test (assumption-proof? (ctx source 4)) false)

!(test (proof-term-evidence-list (ctx proof 4)) ())

!(test
   (fact-evidence-only
      ((rule-ev kb uncertainRule)
       (fact-ev (kb MAIN Nil) factA (A))
       (not-ev source-tag)))
   ((fact-ev (kb MAIN Nil) factA (A)) (not-ev source-tag)))

!(test (rule-evidence-base-name (no_inverse namedRule)) namedRule)

!(test
   (rule-application-name ((inverted namedRule with premiseA premiseB) witness))
   namedRule)

; A symbolic rule head must stay symbolic. Destructuring it as a wrapper creates
; spurious rule names and multiplies every open rule candidate.
!(test
   (let $name (rule-application-name ($rule cpu)) (is-var $name))
   true)

!(test
   (rule-application-evidence (registeredRuleKb MAIN Nil) ($rule cpu))
   ())

!(test
   (let $_result (register-rule-evidence! variableRuleKb $rule)
      (rule-evidence-registered? variableRuleKb concreteRule))
   false)

!(compileadd registeredRuleKb
   (: registeredRule
      (Implication (Premises (Input $x)) (Conclusions (Output $x)))
      (STV 0.8 0.7)))

!(test (rule-evidence-registered? registeredRuleKb registeredRule) true)

!(compileadd sharedRuleKb (: leftFact (Tagged left m) (STV 1.0 0.9)))

!(compileadd sharedRuleKb (: rightFact (Tagged right m) (STV 1.0 0.9)))

!(compileadd sharedRuleKb
   (: sharedProjection
      (Implication
         (Premises (Tagged $path $x))
         (Conclusions (Mid $path $x)))
      (STV 0.6 0.8)))

!(compileadd sharedRuleKb
   (: leftGoal
      (Implication (Premises (Mid left $x)) (Conclusions (Goal $x)))
      (STV 1.0 1.0)))

!(compileadd sharedRuleKb
   (: rightGoal
      (Implication (Premises (Mid right $x)) (Conclusions (Goal $x)))
      (STV 1.0 1.0)))

; Both derivations use sharedProjection. Its uncertainty must enter evidence once,
; so the two Goal proofs are dependent and one dominates instead of revising.
!(test
   (let
      (: (rule-proof $goal-rule (rule-proof sharedProjection $fact))
         (Goal m)
         $tv)
      (query 200 sharedRuleKb (: $prf (Goal m) $tv))
      ((is-member ($goal-rule $fact)
          ((leftGoal leftFact) (rightGoal rightFact)))
       $tv))
   (true (STV 0.6799999999999999 0.56)))

!(mark-logic-rule sharedLogicProjection)

!(compileadd logicRuleKb (: logicLeftFact (Tagged left n) (STV 1.0 0.9)))

!(compileadd logicRuleKb (: logicRightFact (Tagged right n) (STV 1.0 0.9)))

!(compileadd logicRuleKb
   (: sharedLogicProjection
      (Implication
         (Premises (Tagged $path $x))
         (Conclusions (LogicMid $path $x)))
      (STV 0.6 0.8)))

!(compileadd logicRuleKb
   (: logicLeftGoal
      (Implication (Premises (LogicMid left $x)) (Conclusions (LogicGoal $x)))
      (STV 1.0 1.0)))

!(compileadd logicRuleKb
   (: logicRightGoal
      (Implication (Premises (LogicMid right $x)) (Conclusions (LogicGoal $x)))
      (STV 1.0 1.0)))

; Marked logic rules are schemas rather than uncertain KB support. The two
; branches therefore retain disjoint evidence and revision-merge.
!(test
   (query 200 logicRuleKb (: $prf (LogicGoal n) $tv))
   (: (merge/revision
         (rule-proof logicRightGoal
            (rule-proof sharedLogicProjection logicRightFact))
         (rule-proof logicLeftGoal
            (rule-proof sharedLogicProjection logicLeftFact)))
      (LogicGoal n)
      (STV 0.6799999999999999 0.717948717948718)))
