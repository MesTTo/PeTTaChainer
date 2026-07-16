!(import! &self petta_chainer)

!(test
   (mergetvs (STV 0.2 0.0) (STV 0.8 0.0))
   (STV 0.5 0.0))

!(test
   (collapse (forward-target-type (: source (Goal) (STV 1.0 1.0))))
   ((Goal)))

!(test
   (collapse
      (mark-forward-agenda-dirty
         (Goal (coreCorrectnessKb MAIN Nil) source (STV 1.0 1.0))))
   (true))

!(test
   (collapse (aggregate-current-pid-live? () 1))
   (false))

!(test (contains-hash? AtomicStatement) false)

!(test
   (collapse
      (cpu-premise-tv
         FoldAllCompiled
         (coreCorrectnessKb Pattern extractor initial combine finish result-tv)
         (STV 0.4 0.7)))
   ((STV 0.4 0.7)))

!(test
   (collapse
      (cpu-premise-tv
         FoldAllCompiled
         (coreCorrectnessKb Pattern extractor initial combine finish unit-stv)
         (STV 0.4 0.7)))
   ((STV 1.0 1.0)))

; Add a second exact AndFormula result to make the scoring step nondeterministic.
; The scheduler must still emit one confidence bound.
(= (AndFormula (STV 0.25 0.5) (STV 0.4 0.5)) (STV 0.99 0.1))

!(test
   (length
      (collapse
         (premises-expected-confidence
            ((CPU AndFormula ((STV 0.25 0.5) (STV 0.4 0.5)) $mid-tv)
             (CPU MpFormula ((STV 0.8 0.7) $mid-tv) $result-tv)))))
   1)
