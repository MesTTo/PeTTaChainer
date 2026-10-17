(= (chainer-cell-get $key)
   (let $values (collapse (match &chainer_cells (cell $key $value) $value))
      (if (== $values ())
         (Error (cell $key) "the chainer cell holds no value")
         (car-atom $values))))

(= (chainer-cell-write! $key $value)
   (let $_old
      (collapse (match &chainer_cells (cell $key $previous)
         (remove-atom &chainer_cells (cell $key $previous))))
      (add-atom &chainer_cells (cell $key $value))))
