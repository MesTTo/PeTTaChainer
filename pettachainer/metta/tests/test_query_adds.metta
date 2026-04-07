!(import! &self petta_chainer)

!(compileadd queryAddsKb (: pa (A) (STV 1.0 1.0)))

!(compileadd queryAddsKb (: pb (B) (STV 1.0 1.0)))

!(test (not (== (collapse (query 10 queryAddsKb (: $p (A) $tv))) ())) true)

!(test (not (== (collapse (query 10 queryAddsKb (: $p (B) $tv))) ())) true)

!(test (not (== (collapse (query 10 queryAddsKb (: $p (And (A) (B)) $tv))) ())) true)

!(compileadd queryAddsKb2 (: pa2 (A) (STV 1.0 1.0)))

!(compileadd queryAddsKb2 (: pb2 (B) (STV 1.0 1.0)))

!(compileadd queryAddsKb2 (: pc2 (And (C) (D)) (STV 1.0 1.0)))

!(test (not (== (collapse (query 10 queryAddsKb2 (: $p (And (A) (B)) $tv))) ())) true)

!(compileadd queryAddsKb3 (: pa3 (A) (STV 1.0 1.0)))

!(compileadd queryAddsKb3 (: pb3 (B) (STV 1.0 1.0)))

!(compileadd queryAddsKb3 (: pc3 (And (A) (D)) (STV 1.0 1.0)))

!(test (not (== (collapse (query 10 queryAddsKb3 (: $p (And (A) (B)) $tv))) ())) true)
