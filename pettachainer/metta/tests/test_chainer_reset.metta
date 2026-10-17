!(import! &self petta_chainer)

(= (ResetAnswers $kb $type)
   (collapse (query 100 $kb (: $proof $type $tv))))

!(compileadd resetKb (: resetRule (Implication (Premises (ResetPremise $x)) (Conclusions (ResetConclusion $x))) (STV 0.9 0.9)))
!(compileadd resetKb (: resetFact (ResetPremise item) (STV 1.0 0.9)))
!(compileadd otherResetKb (: otherFact (OtherFact) (STV 1.0 1.0)))
!(test (== (ResetAnswers resetKb (ResetConclusion item)) ()) false)
!(test (== (ResetAnswers otherResetKb (OtherFact)) ()) false)

; A reset empties every store a knowledge base or a run wrote, in every knowledge base. The
; stores are read before any query, since a query writes its run's cells again.
!(test (chainer-reset!) true)
!(test (collapse (get-atoms &chainer_cells)) ())
!(test (collapse (get-atoms &goal)) ())
!(test (collapse (get-atoms &kb)) ())
!(test (collapse (get-atoms &rules)) ())
!(test (collapse (get-atoms &kb_source_events)) ())
!(test (ResetAnswers resetKb (ResetConclusion item)) ())
!(test (ResetAnswers otherResetKb (OtherFact)) ())

; The same statements added again answer as they did before the reset.
!(test
   (let* (($first (ResetAnswers resetKb (ResetConclusion item)))
          ($rule (collapse (compileadd resetKb (: resetRule (Implication (Premises (ResetPremise $x)) (Conclusions (ResetConclusion $x))) (STV 0.9 0.9)))))
          ($fact (collapse (compileadd resetKb (: resetFact (ResetPremise item) (STV 1.0 0.9)))))
          ($again (ResetAnswers resetKb (ResetConclusion item)))
          ($reset (chainer-reset!))
          ($rule2 (collapse (compileadd resetKb (: resetRule (Implication (Premises (ResetPremise $x)) (Conclusions (ResetConclusion $x))) (STV 0.9 0.9)))))
          ($fact2 (collapse (compileadd resetKb (: resetFact (ResetPremise item) (STV 1.0 0.9)))))
          ($third (ResetAnswers resetKb (ResetConclusion item))))
      ($first (== $again ()) (== $again $third)))
   (() false true))
