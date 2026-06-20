; Prolog-beam-backed generated-context inference control.
;
; Same branch-control surface as context_inference_control (sections 14.1-14.3),
; but the expensive context search runs in the Prolog beam (section 13.2) and
; exports a normal proof tree to PeTTa. This is the section 15.2 local Bayesian
; island discipline: do the deep search in the island, hand back only the ranked
; result.
;
; This extends context_inference_control with the Prolog-backed beam scorer from
; context_generation_beam. It is useful when the branch viability context is
; deeper than the pure PeTTa depth-3 guard enumerator.

!(import! &self context/context_inference_control)
!(import! &self context/context_generation_beam)
!(import! &self (library lib_import))
!(import_prolog_functions_from_file "./context/context_generation_beam.pl" (context_beam_control_for_branches))

; Scores one branch (sections 14.1-14.3) by running the section 13.2 search in
; the Prolog beam, then projects and certifies it inside the local island.
(= (BuildContextBeamBranchReport
      $max-depth
      $beam-width
      (ContextBranch $name $statement $packets $query-features $action))
   (let* (((ContextBeamAnswer
              $_statement
              $guard
              $side
              $evidence
              $projection
              $support
              $trace
              $beam)
             (context_beam_for_query
                $statement
                $packets
                $query-features
                $max-depth
                $beam-width))
          ($score (ContextTraceScore $trace))
          ($utility (ContextBranchUtilityFromProjection $projection $score))
          ($minimality (BuildContextMinimalityReport $guard $packets $query-features)))
      (ContextBeamBranchReport
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
         $minimality
         $beam)))

(= (ContextBeamBranchReportName
      (ContextBeamBranchReport
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
         $_minimality
         $_beam))
   $name)

(= (ContextBeamBranchReportStatement
      (ContextBeamBranchReport
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
         $_minimality
         $_beam))
   $statement)

(= (ContextBeamBranchReportAction
      (ContextBeamBranchReport
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
         $_minimality
         $_beam))
   $action)

(= (ContextBeamBranchReportGuard
      (ContextBeamBranchReport
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
         $_minimality
         $_beam))
   $guard)

(= (ContextBeamBranchReportProjection
      (ContextBeamBranchReport
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
         $_minimality
         $_beam))
   $projection)

(= (ContextBeamBranchReportUtility
      (ContextBeamBranchReport
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
         $_minimality
         $_beam))
   $utility)

(= (ContextBeamBranchReportMinimality
      (ContextBeamBranchReport
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
         $minimality
         $_beam))
   $minimality)

(= (ContextBeamBranchReportBeam
      (ContextBeamBranchReport
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
         $_minimality
         $beam))
   $beam)

(= (ContextInsertRankedBeamBranchReport () $report)
   (cons $report ()))
(= (ContextInsertRankedBeamBranchReport (cons $head $tail) $report)
   (if (> (ContextBeamBranchReportUtility $report)
          (ContextBeamBranchReportUtility $head))
      (cons $report (cons $head $tail))
      (cons $head (ContextInsertRankedBeamBranchReport $tail $report))))

(= (ContextBeamBranchReportsStep $max-depth $beam-width $reports $branch)
   (ContextInsertRankedBeamBranchReport
      $reports
      (BuildContextBeamBranchReport $max-depth $beam-width $branch)))

(= (ContextBeamBranchReports $branches $max-depth $beam-width)
   (fold-flat
      (ContextBeamBranchReportsStep $max-depth $beam-width)
      ()
      $branches))

(= (ContextFirstBeamBranchReport (cons $head $_tail)) $head)
(= (ContextSecondBeamBranchReport ()) NoContextBeamBranchReport)
(= (ContextSecondBeamBranchReport (cons $_head ())) NoContextBeamBranchReport)
(= (ContextSecondBeamBranchReport (cons $_head (cons $second $_tail))) $second)

(= (ContextBeamBranchReportUtilityOrZero NoContextBeamBranchReport) 0.0)
(= (ContextBeamBranchReportUtilityOrZero $report)
   (ContextBeamBranchReportUtility $report))

(= (ContextBeamBranchReportNameOrNone NoContextBeamBranchReport) none)
(= (ContextBeamBranchReportNameOrNone $report)
   (ContextBeamBranchReportName $report))

(= (ContextBeamBranchReportGuardOrNone NoContextBeamBranchReport) none)
(= (ContextBeamBranchReportGuardOrNone $report)
   (ContextBeamBranchReportGuard $report))

(= (BestContextBeamBranchReport $reports)
   (ContextFirstBeamBranchReport $reports))

(= (ContextBeamBranchDecisionForReport $best-name $report)
   (let $name (ContextBeamBranchReportName $report)
      (if (== $name $best-name)
         (ContextBranchDecision execute $name (ContextBeamBranchReportAction $report))
         (ContextBranchDecision prune $name (ContextBeamBranchReportAction $report)))))

(= (ContextBeamBranchDecisionsStep $best-name $decisions $report)
   (cons (ContextBeamBranchDecisionForReport $best-name $report) $decisions))

(= (ContextBeamBranchDecisions $best-name $reports)
   (fold-flat (ContextBeamBranchDecisionsStep $best-name) () $reports))

(= (GeneratedContextBeamControlForBranches $branches $max-depth $beam-width)
   (context_beam_control_for_branches $branches $max-depth $beam-width))

(= (ContextBeamControlResultBest
      (ContextBeamControlResult $best $_decisions $_reports))
   $best)

(= (ContextBeamControlResultDecisions
      (ContextBeamControlResult $_best $decisions $_reports))
   $decisions)

(= (ContextBeamControlResultReports
       (ContextBeamControlResult $_best $_decisions $reports))
    $reports)

(= (BuildContextBeamControlSelectionAudit
      (ContextBeamControlResult $best $decisions $reports))
   (let* (($runner-up (ContextSecondBeamBranchReport $reports))
          ($best-utility (ContextBeamBranchReportUtility $best))
          ($runner-up-utility (ContextBeamBranchReportUtilityOrZero $runner-up)))
      (ContextBeamControlSelectionAudit
         (ContextBeamBranchReportName $best)
         (ContextBeamBranchReportAction $best)
         $best
         $best-utility
         $runner-up
         $runner-up-utility
         (- $best-utility $runner-up-utility)
         $decisions)))

(= (ContextBeamControlResultSelectionAudit $result)
   (BuildContextBeamControlSelectionAudit $result))

(= (ContextBeamControlSelectionAuditWinner
      (ContextBeamControlSelectionAudit
         $winner
         $_action
         $_best
         $_best-utility
         $_runner-up
         $_runner-up-utility
         $_margin
         $_decisions))
   $winner)

(= (ContextBeamControlSelectionAuditAction
      (ContextBeamControlSelectionAudit
         $_winner
         $action
         $_best
         $_best-utility
         $_runner-up
         $_runner-up-utility
         $_margin
         $_decisions))
   $action)

(= (ContextBeamControlSelectionAuditBestReport
      (ContextBeamControlSelectionAudit
         $_winner
         $_action
         $best
         $_best-utility
         $_runner-up
         $_runner-up-utility
         $_margin
         $_decisions))
   $best)

(= (ContextBeamControlSelectionAuditBestUtility
      (ContextBeamControlSelectionAudit
         $_winner
         $_action
         $_best
         $best-utility
         $_runner-up
         $_runner-up-utility
         $_margin
         $_decisions))
   $best-utility)

(= (ContextBeamControlSelectionAuditRunnerUp
      (ContextBeamControlSelectionAudit
         $_winner
         $_action
         $_best
         $_best-utility
         $runner-up
         $_runner-up-utility
         $_margin
         $_decisions))
   $runner-up)

(= (ContextBeamControlSelectionAuditRunnerUpUtility
      (ContextBeamControlSelectionAudit
         $_winner
         $_action
         $_best
         $_best-utility
         $_runner-up
         $runner-up-utility
         $_margin
         $_decisions))
   $runner-up-utility)

(= (ContextBeamControlSelectionAuditMargin
      (ContextBeamControlSelectionAudit
         $_winner
         $_action
         $_best
         $_best-utility
         $_runner-up
         $_runner-up-utility
         $margin
         $_decisions))
   $margin)

(= (ContextBeamControlSelectionAuditDecisions
      (ContextBeamControlSelectionAudit
         $_winner
         $_action
         $_best
         $_best-utility
         $_runner-up
         $_runner-up-utility
         $_margin
         $decisions))
   $decisions)

(= (BuildContextBeamControlSelectionSummary $audit)
   (ContextBeamControlSelectionSummary
      (ContextBeamControlSelectionAuditWinner $audit)
      (ContextBeamBranchReportGuard
         (ContextBeamControlSelectionAuditBestReport $audit))
      (ContextBeamBranchReportNameOrNone
         (ContextBeamControlSelectionAuditRunnerUp $audit))
      (ContextBeamBranchReportGuardOrNone
         (ContextBeamControlSelectionAuditRunnerUp $audit))
      (ContextBeamControlSelectionAuditMargin $audit)
      (ContextBeamControlSelectionAuditDecisions $audit)))

(= (ContextBeamControlResultToPeTTaChainerResult
      (ContextBeamControlResult $best $decisions $reports))
   (: (context-beam-controlled-proof
         (select-branch
            (ContextBeamBranchReportName $best)
            (ContextBeamBranchReportAction $best))
         (branch-decisions $decisions)
         (ranked-beam-branch-reports $reports)
         (generate-context (ContextBeamBranchReportGuard $best))
         (certify-minimality (ContextBeamBranchReportMinimality $best))
         (project-evidence (ContextBeamBranchReportProjection $best))
         (beam-search (ContextBeamBranchReportBeam $best)))
      (ContextBeamBranchReportStatement $best)
      (ContextBeamBranchReportProjection $best)))

(= (GeneratedContextBeamControlPeTTaChainerResultForBranches $branches $max-depth $beam-width)
   (ContextBeamControlResultToPeTTaChainerResult
      (GeneratedContextBeamControlForBranches $branches $max-depth $beam-width)))

(= (GeneratedContextBeamControlForSpace $space $control $max-depth $beam-width)
   (GeneratedContextBeamControlForBranches
      (ContextControlBranchesFromSpace $space $control)
      $max-depth
      $beam-width))

(= (GeneratedContextBeamControlSelectionAuditForSpace $space $control $max-depth $beam-width)
   (ContextBeamControlResultSelectionAudit
      (GeneratedContextBeamControlForSpace $space $control $max-depth $beam-width)))

(= (GeneratedContextBeamControlPeTTaChainerResultForSpace $space $control $max-depth $beam-width)
   (ContextBeamControlResultToPeTTaChainerResult
      (GeneratedContextBeamControlForSpace $space $control $max-depth $beam-width)))

(= (ContextBeamControlledProofSelectedBranch
      (context-beam-controlled-proof
         (select-branch $name $_action)
         $_decisions
         $_reports
         $_generate
         $_minimality
         $_project
         $_beam))
   $name)

(= (ContextBeamControlledProofSelectedAction
       (context-beam-controlled-proof
          (select-branch $_name $action)
          $_decisions
         $_reports
         $_generate
         $_minimality
         $_project
          $_beam))
    $action)

(= (ContextBeamControlledProofDecisions
      (context-beam-controlled-proof
         $_select
         (branch-decisions $decisions)
         $_reports
         $_generate
         $_minimality
         $_project
         $_beam))
   $decisions)

(= (ContextBeamControlledProofReports
       (context-beam-controlled-proof
          $_select
          $_decisions
         (ranked-beam-branch-reports $reports)
         $_generate
         $_minimality
         $_project
         $_beam))
   $reports)

(= (ContextBeamControlledProofGuard
      (context-beam-controlled-proof
         $_select
         $_decisions
         $_reports
         (generate-context $guard)
         $_minimality
         $_project
         $_beam))
   $guard)

(= (ContextBeamControlledProofBeam
       (context-beam-controlled-proof
          $_select
          $_decisions
         $_reports
         $_generate
         $_minimality
         $_project
          (beam-search $beam)))
    $beam)

(= (ContextBeamControlledProofSelectionAudit $proof)
   (let* (($reports (ContextBeamControlledProofReports $proof))
          ($best (ContextFirstBeamBranchReport $reports))
          ($runner-up (ContextSecondBeamBranchReport $reports))
          ($best-utility (ContextBeamBranchReportUtility $best))
          ($runner-up-utility (ContextBeamBranchReportUtilityOrZero $runner-up)))
      (ContextBeamControlSelectionAudit
         (ContextBeamBranchReportName $best)
         (ContextBeamBranchReportAction $best)
         $best
         $best-utility
         $runner-up
         $runner-up-utility
         (- $best-utility $runner-up-utility)
         (ContextBeamControlledProofDecisions $proof))))

(= (ContextBeamControlledResultProof (: $proof $_statement $_projection)) $proof)
(= (ContextBeamControlledResultStatement (: $_proof $statement $_projection)) $statement)
(= (ContextBeamControlledResultProjection (: $_proof $_statement $projection)) $projection)
