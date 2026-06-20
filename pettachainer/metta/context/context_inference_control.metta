; Generated-context inference control.
;
; Practical inference control over generated contexts, sections 14.1-14.3. Each
; delayed chainer branch gets a generated context, an STV projection, a utility
; (the section 14.2 Priority scalar projection, utility = s*c + 0.10*score), and
; a minimality certificate. The controller emits execute/prune decisions and a
; utility-ranked audit. The selection-shift heads are revision as an
; inference-control action (sections 11, 14.3): when new evidence arrives the
; local context is regenerated and the winning branch can flip.
;
; The PLN inference-control experiment in the trueagi-io/chaining repo scores
; delayed chainer branches before running them. This module uses the generated
; context scorer as that branch estimator: each candidate branch gets its own
; generated context, evidence projection, score trace, and ablation certificate.

!(import! &self context/context_generation)

(= (ContextProjectionStrength (STV $strength $_confidence)) $strength)
(= (ContextProjectionConfidence (STV $_strength $confidence)) $confidence)

; The section 14.2 Priority scalar projection: utility = s*c + 0.10*score.
(= (ContextBranchUtilityFromProjection $projection $score)
   (+ (* (ContextProjectionStrength $projection)
         (ContextProjectionConfidence $projection))
      (* 0.10 $score)))

(= (BuildContextBranchReport
      (ContextBranch $name $statement $packets $query-features $action))
   (let* (((ContextExplanation
              $_statement
              $guard
              $side
              $evidence
              $projection
              $support
              $trace)
             (GeneratedContextExplanationForQuery
                $statement
                $packets
                $query-features))
          ($score (ContextTraceScore $trace))
          ($utility (ContextBranchUtilityFromProjection $projection $score))
          ($minimality (BuildContextMinimalityReport $guard $packets $query-features)))
      (ContextBranchReport
         $name
         $statement
         $action
         $guard
         $side
         $evidence
         $projection
         $score
         $utility
         $support
         $trace
         $minimality)))

(= (ContextBranchReportName
      (ContextBranchReport
         $name
         $_statement
         $_action
         $_guard
         $_side
         $_evidence
         $_projection
         $_score
         $_utility
         $_support
         $_trace
         $_minimality))
   $name)

(= (ContextBranchReportStatement
      (ContextBranchReport
         $_name
         $statement
         $_action
         $_guard
         $_side
         $_evidence
         $_projection
         $_score
         $_utility
         $_support
         $_trace
         $_minimality))
   $statement)

(= (ContextBranchReportAction
      (ContextBranchReport
         $_name
         $_statement
         $action
         $_guard
         $_side
         $_evidence
         $_projection
         $_score
         $_utility
         $_support
         $_trace
         $_minimality))
   $action)

(= (ContextBranchReportGuard
      (ContextBranchReport
         $_name
         $_statement
         $_action
         $guard
         $_side
         $_evidence
         $_projection
         $_score
         $_utility
         $_support
         $_trace
         $_minimality))
   $guard)

(= (ContextBranchReportProjection
      (ContextBranchReport
         $_name
         $_statement
         $_action
         $_guard
         $_side
         $_evidence
         $projection
         $_score
         $_utility
         $_support
         $_trace
         $_minimality))
   $projection)

(= (ContextBranchReportUtility
      (ContextBranchReport
         $_name
         $_statement
         $_action
         $_guard
         $_side
         $_evidence
         $_projection
         $_score
         $utility
         $_support
         $_trace
         $_minimality))
   $utility)

(= (ContextInsertRankedBranchReport () $report)
   (cons $report ()))
(= (ContextInsertRankedBranchReport (cons $head $tail) $report)
   (if (> (ContextBranchReportUtility $report)
          (ContextBranchReportUtility $head))
      (cons $report (cons $head $tail))
      (cons $head (ContextInsertRankedBranchReport $tail $report))))

(= (ContextBranchReportsStep $reports $branch)
   (ContextInsertRankedBranchReport $reports (BuildContextBranchReport $branch)))

(= (ContextBranchReports $branches)
   (fold-flat ContextBranchReportsStep () $branches))

(= (ContextFirstBranchReport (cons $head $_tail)) $head)
(= (ContextSecondBranchReport ()) NoContextBranchReport)
(= (ContextSecondBranchReport (cons $_head ())) NoContextBranchReport)
(= (ContextSecondBranchReport (cons $_head (cons $second $_tail))) $second)

(= (ContextBranchReportUtilityOrZero NoContextBranchReport) 0.0)
(= (ContextBranchReportUtilityOrZero $report)
   (ContextBranchReportUtility $report))

(= (ContextBranchReportMinimality
      (ContextBranchReport
         $_name
         $_statement
         $_action
         $_guard
         $_side
         $_evidence
         $_projection
         $_score
         $_utility
         $_support
         $_trace
         $minimality))
   $minimality)

(= (ContextBetterBranchReport NoContextBranchReport $report) $report)
(= (ContextBetterBranchReport $best $report)
   (if (> (ContextBranchReportUtility $report)
          (ContextBranchReportUtility $best))
      $report
      $best))

(= (BestContextBranchReport $reports)
   (fold-flat ContextBetterBranchReport NoContextBranchReport $reports))

(= (ContextBranchDecisionForReport $best-name $report)
   (let $name (ContextBranchReportName $report)
      (if (== $name $best-name)
         (ContextBranchDecision execute $name (ContextBranchReportAction $report))
         (ContextBranchDecision prune $name (ContextBranchReportAction $report)))))

(= (ContextBranchDecisionsStep $best-name $decisions $report)
   (cons (ContextBranchDecisionForReport $best-name $report) $decisions))

(= (ContextBranchDecisions $best-name $reports)
   (fold-flat (ContextBranchDecisionsStep $best-name) () $reports))

(= (GeneratedContextControlForBranches $branches)
   (let* (($reports (ContextBranchReports $branches))
          ($best (BestContextBranchReport $reports))
          ($best-name (ContextBranchReportName $best)))
      (ContextControlResult
         $best
         (ContextBranchDecisions $best-name $reports)
         $reports)))

(= (ContextControlResultBest
      (ContextControlResult $best $_decisions $_reports))
   $best)

(= (ContextControlResultDecisions
      (ContextControlResult $_best $decisions $_reports))
   $decisions)

(= (ContextControlResultReports
       (ContextControlResult $_best $_decisions $reports))
    $reports)

(= (BuildContextControlSelectionAudit
      (ContextControlResult $best $decisions $reports))
   (let* (($runner-up (ContextSecondBranchReport $reports))
          ($best-utility (ContextBranchReportUtility $best))
          ($runner-up-utility (ContextBranchReportUtilityOrZero $runner-up)))
      (ContextControlSelectionAudit
         (ContextBranchReportName $best)
         (ContextBranchReportAction $best)
         $best
         $best-utility
         $runner-up
         $runner-up-utility
         (- $best-utility $runner-up-utility)
         $decisions)))

(= (ContextControlResultSelectionAudit $result)
   (BuildContextControlSelectionAudit $result))

(= (ContextControlSelectionAuditWinner
      (ContextControlSelectionAudit
         $winner
         $_action
         $_best
         $_best-utility
         $_runner-up
         $_runner-up-utility
         $_margin
         $_decisions))
   $winner)

(= (ContextControlSelectionAuditAction
      (ContextControlSelectionAudit
         $_winner
         $action
         $_best
         $_best-utility
         $_runner-up
         $_runner-up-utility
         $_margin
         $_decisions))
   $action)

(= (ContextControlSelectionAuditBestReport
      (ContextControlSelectionAudit
         $_winner
         $_action
         $best
         $_best-utility
         $_runner-up
         $_runner-up-utility
         $_margin
         $_decisions))
   $best)

(= (ContextControlSelectionAuditBestUtility
      (ContextControlSelectionAudit
         $_winner
         $_action
         $_best
         $best-utility
         $_runner-up
         $_runner-up-utility
         $_margin
         $_decisions))
   $best-utility)

(= (ContextControlSelectionAuditRunnerUp
      (ContextControlSelectionAudit
         $_winner
         $_action
         $_best
         $_best-utility
         $runner-up
         $_runner-up-utility
         $_margin
         $_decisions))
   $runner-up)

(= (ContextControlSelectionAuditRunnerUpUtility
      (ContextControlSelectionAudit
         $_winner
         $_action
         $_best
         $_best-utility
         $_runner-up
         $runner-up-utility
         $_margin
         $_decisions))
   $runner-up-utility)

(= (ContextControlSelectionAuditMargin
      (ContextControlSelectionAudit
         $_winner
         $_action
         $_best
         $_best-utility
         $_runner-up
         $_runner-up-utility
         $margin
         $_decisions))
   $margin)

(= (ContextControlSelectionAuditDecisions
      (ContextControlSelectionAudit
         $_winner
         $_action
         $_best
         $_best-utility
         $_runner-up
         $_runner-up-utility
         $_margin
         $decisions))
   $decisions)

(= (ContextControlSelectionChanged $before $after)
   (if (== (ContextControlSelectionAuditWinner $before)
           (ContextControlSelectionAuditWinner $after))
      False
      True))

; Revision as an inference-control action (sections 11, 14.3): compare the audit
; before and after new evidence, so a regenerated context can flip the winner.
(= (BuildContextControlSelectionShift $before $after)
   (ContextControlSelectionShift
      (ContextControlSelectionAuditWinner $before)
      (ContextControlSelectionAuditWinner $after)
      (ContextControlSelectionAuditAction $before)
      (ContextControlSelectionAuditAction $after)
      (ContextBranchReportGuard
         (ContextControlSelectionAuditBestReport $before))
      (ContextBranchReportGuard
         (ContextControlSelectionAuditBestReport $after))
      (ContextControlSelectionAuditMargin $before)
      (ContextControlSelectionAuditMargin $after)
      (ContextControlSelectionChanged $before $after)
      $before
      $after))

(= (ContextControlSelectionShiftPreviousWinner
      (ContextControlSelectionShift
         $previous-winner
         $_new-winner
         $_previous-action
         $_new-action
         $_previous-guard
         $_new-guard
         $_previous-margin
         $_new-margin
         $_changed
         $_before
         $_after))
   $previous-winner)

(= (ContextControlSelectionShiftNewWinner
      (ContextControlSelectionShift
         $_previous-winner
         $new-winner
         $_previous-action
         $_new-action
         $_previous-guard
         $_new-guard
         $_previous-margin
         $_new-margin
         $_changed
         $_before
         $_after))
   $new-winner)

(= (ContextControlSelectionShiftPreviousAction
      (ContextControlSelectionShift
         $_previous-winner
         $_new-winner
         $previous-action
         $_new-action
         $_previous-guard
         $_new-guard
         $_previous-margin
         $_new-margin
         $_changed
         $_before
         $_after))
   $previous-action)

(= (ContextControlSelectionShiftNewAction
      (ContextControlSelectionShift
         $_previous-winner
         $_new-winner
         $_previous-action
         $new-action
         $_previous-guard
         $_new-guard
         $_previous-margin
         $_new-margin
         $_changed
         $_before
         $_after))
   $new-action)

(= (ContextControlSelectionShiftPreviousGuard
      (ContextControlSelectionShift
         $_previous-winner
         $_new-winner
         $_previous-action
         $_new-action
         $previous-guard
         $_new-guard
         $_previous-margin
         $_new-margin
         $_changed
         $_before
         $_after))
   $previous-guard)

(= (ContextControlSelectionShiftNewGuard
      (ContextControlSelectionShift
         $_previous-winner
         $_new-winner
         $_previous-action
         $_new-action
         $_previous-guard
         $new-guard
         $_previous-margin
         $_new-margin
         $_changed
         $_before
         $_after))
   $new-guard)

(= (ContextControlSelectionShiftPreviousMargin
      (ContextControlSelectionShift
         $_previous-winner
         $_new-winner
         $_previous-action
         $_new-action
         $_previous-guard
         $_new-guard
         $previous-margin
         $_new-margin
         $_changed
         $_before
         $_after))
   $previous-margin)

(= (ContextControlSelectionShiftNewMargin
      (ContextControlSelectionShift
         $_previous-winner
         $_new-winner
         $_previous-action
         $_new-action
         $_previous-guard
         $_new-guard
         $_previous-margin
         $new-margin
         $_changed
         $_before
         $_after))
   $new-margin)

(= (ContextControlSelectionShiftChanged
      (ContextControlSelectionShift
         $_previous-winner
         $_new-winner
         $_previous-action
         $_new-action
         $_previous-guard
         $_new-guard
         $_previous-margin
         $_new-margin
         $changed
         $_before
         $_after))
   $changed)

(= (ContextControlSelectionShiftBefore
      (ContextControlSelectionShift
         $_previous-winner
         $_new-winner
         $_previous-action
         $_new-action
         $_previous-guard
         $_new-guard
         $_previous-margin
         $_new-margin
         $_changed
         $before
         $_after))
   $before)

(= (ContextControlSelectionShiftAfter
      (ContextControlSelectionShift
         $_previous-winner
         $_new-winner
         $_previous-action
         $_new-action
         $_previous-guard
         $_new-guard
         $_previous-margin
         $_new-margin
         $_changed
         $_before
         $after))
   $after)

(= (BuildContextControlSelectionShiftSummary $shift)
   (ContextControlSelectionShiftSummary
      (ContextControlSelectionShiftPreviousWinner $shift)
      (ContextControlSelectionShiftNewWinner $shift)
      (ContextControlSelectionShiftPreviousGuard $shift)
      (ContextControlSelectionShiftNewGuard $shift)
      (ContextControlSelectionShiftNewMargin $shift)
      (ContextControlSelectionShiftChanged $shift)))

(= (ContextControlResultToPeTTaChainerResult
      (ContextControlResult $best $decisions $reports))
   (: (context-controlled-proof
         (select-branch
            (ContextBranchReportName $best)
            (ContextBranchReportAction $best))
         (branch-decisions $decisions)
         (ranked-branch-reports $reports)
         (generate-context (ContextBranchReportGuard $best))
         (certify-minimality (ContextBranchReportMinimality $best))
         (project-evidence (ContextBranchReportProjection $best)))
      (ContextBranchReportStatement $best)
      (ContextBranchReportProjection $best)))

(= (GeneratedContextControlPeTTaChainerResultForBranches $branches)
   (ContextControlResultToPeTTaChainerResult
      (GeneratedContextControlForBranches $branches)))

(= (ContextControlCandidatesFromSpace $space $control)
   (collapse
      (match $space
         (ContextControlCandidate $control $name $statement $action)
         (ContextControlCandidateData $name $statement $action))))

(= (ContextControlEvidencePacketsFromSpace $space $control $name)
   (collapse
      (match $space
         (ContextControlEvidence $control $name $statement $evidence $features $provenance)
         (EvidencePacket $statement $evidence $features $provenance))))

(= (ContextControlQueryFeaturesFromSpace $space $control $name $statement)
   (fold-flat
      ContextFeatureUnionListStep
      (fold-flat
         ContextFeatureUnionListStep
         ()
         (collapse
            (match $space
               (ContextControlEvidence $control $name $statement $_evidence $features $_provenance)
               $features)))
      (collapse
         (match $space
            (ContextControlQueryFeatures $control $name $features)
            $features))))

(= (ContextControlCandidateToBranch
      $space
      $control
      (ContextControlCandidateData $name $statement $action))
   (ContextBranch
      $name
      $statement
      (ContextControlEvidencePacketsFromSpace $space $control $name)
      (ContextControlQueryFeaturesFromSpace $space $control $name $statement)
      $action))

(= (ContextControlBranchesFromSpaceStep $space $control $branches $candidate)
   (cons (ContextControlCandidateToBranch $space $control $candidate) $branches))

(= (ContextControlBranchesFromSpace $space $control)
   (fold-flat
      (ContextControlBranchesFromSpaceStep $space $control)
      ()
      (ContextControlCandidatesFromSpace $space $control)))

(= (GeneratedContextControlForSpace $space $control)
   (GeneratedContextControlForBranches
      (ContextControlBranchesFromSpace $space $control)))

(= (GeneratedContextControlSelectionAuditForSpace $space $control)
   (ContextControlResultSelectionAudit
      (GeneratedContextControlForSpace $space $control)))

(= (GeneratedContextControlPeTTaChainerResultForSpace $space $control)
   (ContextControlResultToPeTTaChainerResult
      (GeneratedContextControlForSpace $space $control)))

(= (ContextControlledProofSelectedBranch
      (context-controlled-proof
         (select-branch $name $_action)
         $_decisions
         $_reports
         $_generate
         $_minimality
         $_project))
   $name)

(= (ContextControlledProofSelectedAction
      (context-controlled-proof
         (select-branch $_name $action)
         $_decisions
         $_reports
         $_generate
         $_minimality
         $_project))
   $action)

(= (ContextControlledProofDecisions
      (context-controlled-proof
         $_select
         (branch-decisions $decisions)
         $_reports
         $_generate
         $_minimality
         $_project))
   $decisions)

(= (ContextControlledProofReports
      (context-controlled-proof
         $_select
         $_decisions
         (ranked-branch-reports $reports)
         $_generate
         $_minimality
         $_project))
   $reports)

(= (ContextControlledProofGuard
       (context-controlled-proof
          $_select
          $_decisions
         $_reports
         (generate-context $guard)
         $_minimality
          $_project))
    $guard)

(= (ContextControlledProofSelectionAudit $proof)
   (let* (($reports (ContextControlledProofReports $proof))
          ($best (ContextFirstBranchReport $reports))
          ($runner-up (ContextSecondBranchReport $reports))
          ($best-utility (ContextBranchReportUtility $best))
          ($runner-up-utility (ContextBranchReportUtilityOrZero $runner-up)))
      (ContextControlSelectionAudit
         (ContextBranchReportName $best)
         (ContextBranchReportAction $best)
         $best
         $best-utility
         $runner-up
         $runner-up-utility
         (- $best-utility $runner-up-utility)
         (ContextControlledProofDecisions $proof))))

(= (ContextControlledResultProof (: $proof $_statement $_projection)) $proof)
(= (ContextControlledResultStatement (: $_proof $statement $_projection)) $statement)
(= (ContextControlledResultProjection (: $_proof $_statement $projection)) $projection)
