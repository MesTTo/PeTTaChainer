# PeTTaChainer LLM Rule Spec

This spec focuses only on constructing valid Statements and Queries.
It does not describe how to invoke chainer interface functions.

## Core Forms

- Statement form (fact or rule assertion):

```metta
(: proof-id type tv)
```

- Query pattern form:

```metta
(: $proofVar typePattern $tvVar)
```

## Rule Template

```metta
(: ruleName
    (Implication
        (Premises
            premise1
            premise2)
        (Conclusions
            conclusion1))
    (STV 1.0 1.0))
```

## Premise Helpers You Can Use

### Compute

```metta
(Compute f (arg1 arg2 ...) -> $out)
```

### Not

```metta
(Not expr)
```

### GreaterThan / >

```metta
(GreaterThan $distA 5)
(GreaterThan $distA $distB)
```

### MapDist

```metta
(MapDist f (DistFactA ... $inDist) $inDist -> $outDist)
```

### Map2Dist

```metta
(Map2Dist f (DistFactA ... $distA) $distA (DistFactB ... $distB) $distB -> $outDist)
```

### AverageDist

```metta
(AverageDist (DistFactPattern ... $inDist) $inDist -> $outDist)
```

### FoldAll / FoldAllValue

```metta
(FoldAll pattern value init fold-fn -> out)
(FoldAllValue pattern init fold-fn -> out)
```

## TV Modeling Rules

- `STV` is truth uncertainty only.
- Distribution TVs (`ParticleDist`, `NatDist`, `FloatDist`) are value uncertainty.
- For uncertain numeric values, use distribution TVs.

Good:

```metta
(: h1 (HeightDist g1 alice (PointMass 160.0)) (STV 1.0 1.0))
(: h2 (HeightDist g1 bob (ParticleFromNormal 170.0 2.0)) (STV 1.0 1.0))
```

Avoid encoding numeric values in `STV` strength for measurement semantics.

## Distribution Constructors

```metta
(PointMass x)
(ParticleFromNormal mu sigma)
(ParticleFromPairs ((x1 w1) (x2 w2) ...))
```

## Example: Average Height Rule

```metta
(: avgHeightDistRule
    (Implication
        (Premises
            (Group $g)
            (AverageDist (HeightDist $g $person $heightDist) $heightDist -> $avgDist))
        (Conclusions
            (AvgHeightDist $g $avgDist)))
    (STV 1.0 1.0))

(: $prf (AvgHeightDist g1 $avgDist) $tv)
```

## Example: Rectangle Area Rule

```metta
(: areaDistRule
    (Implication
        (Premises
            (Rectangle $rect)
            (Map2Dist *
                (LengthDist $rect $lengthDist)
                $lengthDist
                (WidthDist $rect $widthDist)
                $widthDist
                ->
                $areaDist))
        (Conclusions
            (AreaDist $rect $areaDist)))
    (STV 1.0 1.0))

(: $prf (AreaDist rectA $areaDist) $tv)
```

## Contextual Queries (πPLN)

The chainer can generate a local context from stored evidence and project a query
under it, the πPLN exception-finding path. Evidence is a count pair
`(EC pos neg)`, positive and negative support kept separate, projected to an STV
by `s = (pos + k*p0) / (pos + neg + k)`.

To get the generated-context projection alongside the normal proofs, use the
Python `contextual_query` (see the README) or the MeTTa heads
`GeneratedContextForKBStatement` and `ContextProjectionAtomForQuery`. You write
statements and queries exactly as above; the context is derived from the features
on the stored atoms, so the query itself needs no special syntax.
