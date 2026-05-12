!(import! &self petta_chainer)
!(import! &data data_test)

!(compileadd kb (: r1 (Implication (Premises (Feature a)) (Conclusions (Target))) (STV 1.0 0.5)))
!(compileadd kb (: r2 (Implication (Premises (Feature a)) (Conclusions (Feature c))) (STV 1.0 0.5)))
!(compileadd kb (: r3 (Implication (Premises (Feature c)) (Conclusions (Target))) (STV 1.0 0.5)))

!(=================================)

!(query 100 kb (: $prf (Implication (Premises (Feature a)) (Conclusions (Target))) $tv))
