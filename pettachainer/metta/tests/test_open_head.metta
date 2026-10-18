; Purpose: checks that the tests asking whether an expression's head is a variable answer as
; PeTTa does on every engine, pymetta holding is-var's argument unreduced: a variable head, a
; symbol head, a symbol and the empty expression, and the two materialisers that branch on it.

!(import! &self petta_chainer)

; am[verifies a-pc-is-var-bound-1018@d0a970]
!(test (collapse (expr-head-var? ($p b))) (true))
!(test (collapse (expr-head-var? (f b))) (false))
!(test (collapse (expr-head-var? a)) (false))
!(test (collapse (expr-head-var? ())) (false))

; A rule proof whose head is a variable stands for its argument; any other is a rule-proof.
; am[verifies a-pc-is-var-bound-1018@d0a970]
!(test (materialize-rule-proof-expression ($rule x)) x)
!(test (materialize-rule-proof-expression (rule x)) (rule-proof rule x))

; A term whose head is a variable keeps it as its head while its arguments are materialised.
; am[verifies a-pc-is-var-bound-1018@d0a970]
!(test
   (let $term (materialize-proof-refs ($head a (b c)))
      ((expr-head-var? $term) (cdr-atom $term)))
   (true (a (b c))))
