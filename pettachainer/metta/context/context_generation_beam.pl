packet_features(['EvidencePacket', _Statement, _Evidence, Features, _Provenance], Features).

packet_parts(
    ['EvidencePacket', Statement, ['EC', Pos, Neg], Features, Provenance],
    Statement,
    Pos,
    Neg,
    Features,
    Provenance
).

unique_preserve(Items, Unique) :-
    unique_preserve_(Items, [], Reversed),
    reverse(Reversed, Unique).

unique_preserve_([], Seen, Seen).
unique_preserve_([Item|Rest], Seen, Unique) :-
    (   memberchk(Item, Seen)
    ->  unique_preserve_(Rest, Seen, Unique)
    ;   unique_preserve_(Rest, [Item|Seen], Unique)
    ).

all_features(Packets, Features) :-
    findall(
        Feature,
        (   member(Packet, Packets),
            packet_features(Packet, PacketFeatures),
            member(Feature, PacketFeatures)
        ),
        RawFeatures
    ),
    unique_preserve(RawFeatures, Features).

combination(0, _Items, []) :- !.
combination(K, [Item|Rest], [Item|Chosen]) :-
    K > 0,
    K1 is K - 1,
    combination(K1, Rest, Chosen).
combination(K, [_Item|Rest], Chosen) :-
    K > 0,
    combination(K, Rest, Chosen).

guard_from_features([Feature], Feature) :- !.
guard_from_features([Feature|Rest], ['ContextAnd', Feature, GuardRest]) :-
    guard_from_features(Rest, GuardRest).

guard_arity(['ContextAnd', Left, Right], Arity) :- !,
    guard_arity(Left, LeftArity),
    guard_arity(Right, RightArity),
    Arity is LeftArity + RightArity.
guard_arity(_Feature, 1).

guard_matches(['ContextAnd', Left, Right], Features) :- !,
    guard_matches(Left, Features),
    guard_matches(Right, Features).
guard_matches(Feature, Features) :-
    memberchk(Feature, Features).

guard_matches_bool(Guard, Features, true) :-
    guard_matches(Guard, Features),
    !.
guard_matches_bool(_Guard, _Features, false).

all_evidence([], 0.0, 0.0).
all_evidence([Packet|Rest], Pos, Neg) :-
    packet_parts(Packet, _Statement, PacketPos, PacketNeg, _Features, _Provenance),
    all_evidence(Rest, RestPos, RestNeg),
    Pos is PacketPos + RestPos,
    Neg is PacketNeg + RestNeg.

split_counts(_Guard, [], 0.0, 0.0, 0.0, 0.0).
split_counts(Guard, [Packet|Rest], InPos, InNeg, OutPos, OutNeg) :-
    packet_parts(Packet, _Statement, PacketPos, PacketNeg, Features, _Provenance),
    split_counts(Guard, Rest, RestInPos, RestInNeg, RestOutPos, RestOutNeg),
    (   guard_matches(Guard, Features)
    ->  InPos is RestInPos + PacketPos,
        InNeg is RestInNeg + PacketNeg,
        OutPos is RestOutPos,
        OutNeg is RestOutNeg
    ;   InPos is RestInPos,
        InNeg is RestInNeg,
        OutPos is RestOutPos + PacketPos,
        OutNeg is RestOutNeg + PacketNeg
    ).

conflict(Pos, Neg, Conflict) :-
    Total is Pos + Neg,
    (   Total =< 0.0
    ->  Conflict = 0.0
    ;   Smaller is min(Pos, Neg),
        Conflict is (2.0 * Smaller) / Total
    ).

weighted_split_conflict(InPos, InNeg, OutPos, OutNeg, Conflict) :-
    InTotal is InPos + InNeg,
    OutTotal is OutPos + OutNeg,
    Total is InTotal + OutTotal,
    (   Total =< 0.0
    ->  Conflict = 0.0
    ;   conflict(InPos, InNeg, InConflict),
        conflict(OutPos, OutNeg, OutConflict),
        Conflict is ((InConflict * InTotal) + (OutConflict * OutTotal)) / Total
    ).

focus_bonus(Guard, QueryFeatures, Bonus) :-
    (   guard_matches(Guard, QueryFeatures)
    ->  guard_arity(Guard, Arity),
        (Arity > 1 -> Bonus = 0.75 ; Bonus = 0.8)
    ;   Bonus = 0.0
    ).

feature_penalty(none, 0.0) :- !.
feature_penalty(['ContextAnd', Left, Right], Penalty) :- !,
    guard_arity(['ContextAnd', Left, Right], Arity),
    Penalty is 0.02 + (0.04 * Arity).
feature_penalty([type, _Type], 0.02) :- !.
feature_penalty([habitat, _Habitat], 0.03) :- !.
feature_penalty(_Feature, 0.05).

single_sided_score(Guard, QueryFeatures, InTotal, OutTotal, Score) :-
    (   guard_matches(Guard, QueryFeatures)
    ->  (   InTotal > 0.0
        ->  focus_bonus(Guard, QueryFeatures, FocusBonus),
            feature_penalty(Guard, Penalty),
            Score is FocusBonus - Penalty
        ;   Score = -9999.0
        )
    ;   (   OutTotal > 0.0
        ->  feature_penalty(Guard, Penalty),
            Score is 0.0 - Penalty
        ;   Score = -9999.0
        )
    ).

score_guard(Guard, Packets, QueryFeatures, Score, Trace) :-
    all_evidence(Packets, ParentPos, ParentNeg),
    split_counts(Guard, Packets, InPos, InNeg, OutPos, OutNeg),
    InTotal is InPos + InNeg,
    OutTotal is OutPos + OutNeg,
    (   InTotal =< 0.0
    ;   OutTotal =< 0.0
    ),
    !,
    conflict(ParentPos, ParentNeg, ParentConflict),
    weighted_split_conflict(InPos, InNeg, OutPos, OutNeg, SplitConflict),
    Reduction is ParentConflict - SplitConflict,
    focus_bonus(Guard, QueryFeatures, FocusBonus),
    feature_penalty(Guard, Penalty),
    single_sided_score(Guard, QueryFeatures, InTotal, OutTotal, Score),
    Trace = [
        'ContextScoreTrace',
        Guard,
        ['ParentEvidence', ['EC', ParentPos, ParentNeg]],
        ['SplitCounts', InPos, InNeg, OutPos, OutNeg],
        ['ParentConflict', ParentConflict],
        ['SplitConflict', SplitConflict],
        ['ConflictReduction', Reduction],
        ['FocusBonus', FocusBonus],
        ['Penalty', Penalty],
        ['Score', Score]
    ].
score_guard(Guard, Packets, QueryFeatures, Score, Trace) :-
    all_evidence(Packets, ParentPos, ParentNeg),
    split_counts(Guard, Packets, InPos, InNeg, OutPos, OutNeg),
    conflict(ParentPos, ParentNeg, ParentConflict),
    weighted_split_conflict(InPos, InNeg, OutPos, OutNeg, SplitConflict),
    Reduction is ParentConflict - SplitConflict,
    focus_bonus(Guard, QueryFeatures, FocusBonus),
    feature_penalty(Guard, Penalty),
    Score is Reduction + FocusBonus - Penalty,
    Trace = [
        'ContextScoreTrace',
        Guard,
        ['ParentEvidence', ['EC', ParentPos, ParentNeg]],
        ['SplitCounts', InPos, InNeg, OutPos, OutNeg],
        ['ParentConflict', ParentConflict],
        ['SplitConflict', SplitConflict],
        ['ConflictReduction', Reduction],
        ['FocusBonus', FocusBonus],
        ['Penalty', Penalty],
        ['Score', Score]
    ].

candidate_report(Packets, QueryFeatures, Guard, Key-Report) :-
    score_guard(Guard, Packets, QueryFeatures, Score, Trace),
    Key is -Score,
    Report = ['CandidateReport', Guard, Trace].

take_reports(0, _Pairs, []) :- !.
take_reports(_N, [], []) :- !.
take_reports(N, [_Key-Report|Rest], [Report|Taken]) :-
    N > 0,
    N1 is N - 1,
    take_reports(N1, Rest, Taken).

selected_evidence(Guard, QueryFeatures, Packets, Side, ['EC', Pos, Neg]) :-
    split_counts(Guard, Packets, InPos, InNeg, OutPos, OutNeg),
    (   guard_matches(Guard, QueryFeatures)
    ->  Side = inside,
        Pos = InPos,
        Neg = InNeg
    ;   Side = outside,
        Pos = OutPos,
        Neg = OutNeg
    ).

project_stv(['EC', Pos, Neg], P0, K, ['STV', Strength, Confidence]) :-
    N is Pos + Neg,
    Den is N + K,
    (   Den =< 0.0
    ->  Strength = P0,
        Confidence = 0.0
    ;   Strength is (Pos + (K * P0)) / Den,
        Confidence is N / Den
    ).

support_packets(Guard, QueryFeatures, Packets, Support) :-
    guard_matches_bool(Guard, QueryFeatures, QueryInside),
    findall(
        ['SupportPacket', Statement, ['EC', Pos, Neg], Features, Provenance],
        (   member(Packet, Packets),
            packet_parts(Packet, Statement, Pos, Neg, Features, Provenance),
            guard_matches_bool(Guard, Features, PacketInside),
            QueryInside == PacketInside
        ),
        Support
    ).

context_beam_for_query(Statement, Packets, QueryFeatures, MaxDepth0, BeamWidth0, Answer) :-
    MaxDepth is round(MaxDepth0),
    BeamWidth is round(BeamWidth0),
    all_features(Packets, Features),
    findall(
        Guard,
        (   between(1, MaxDepth, Depth),
            combination(Depth, Features, ChosenFeatures),
            guard_from_features(ChosenFeatures, Guard)
        ),
        Guards0
    ),
    unique_preserve(Guards0, Guards),
    findall(Pair, (member(Guard, Guards), candidate_report(Packets, QueryFeatures, Guard, Pair)), Pairs),
    keysort(Pairs, SortedPairs),
    take_reports(BeamWidth, SortedPairs, BeamReports),
    (   BeamReports = [['CandidateReport', BestGuard, BestTrace]|_]
    ->  selected_evidence(BestGuard, QueryFeatures, Packets, Side, Evidence),
        project_stv(Evidence, 0.95, 2.0, Projection),
        support_packets(BestGuard, QueryFeatures, Packets, Support),
        Answer = [
            'ContextBeamAnswer',
            Statement,
            BestGuard,
            Side,
            Evidence,
            Projection,
            Support,
            BestTrace,
            ['Beam', BeamReports]
        ]
    ;   Answer = [
            'ContextBeamAnswer',
            Statement,
            none,
            outside,
            ['EC', 0.0, 0.0],
            ['STV', 0.95, 0.0],
            [],
            ['ContextScoreTrace', none],
            ['Beam', []]
        ]
    ).

trace_score(
    [
        'ContextScoreTrace',
        _Guard,
        _Parent,
        _Split,
        _ParentConflict,
        _SplitConflict,
        _Reduction,
        _Focus,
        _Penalty,
        ['Score', Score]
    ],
    Score
).

projection_utility(['STV', Strength, Confidence], Score, Utility) :-
    Utility is (Strength * Confidence) + (0.10 * Score).

branch_parts(
    ['ContextBranch', Name, Statement, Packets, QueryFeatures, Action],
    Name,
    Statement,
    Packets,
    QueryFeatures,
    Action
).

guard_atoms(none, []) :- !.
guard_atoms(['ContextAnd', Left, Right], Atoms) :- !,
    guard_atoms(Left, LeftAtoms),
    guard_atoms(Right, RightAtoms),
    append(LeftAtoms, RightAtoms, Atoms).
guard_atoms(Feature, [Feature]).

guard_from_atoms([], none) :- !.
guard_from_atoms([Feature], Feature) :- !.
guard_from_atoms([Feature|Rest], ['ContextAnd', Feature, RestGuard]) :-
    guard_from_atoms(Rest, RestGuard).

remove_feature(_Feature, [], []).
remove_feature(Feature, [Feature|Rest], Reduced) :- !,
    remove_feature(Feature, Rest, Reduced).
remove_feature(Feature, [Head|Rest], [Head|Reduced]) :-
    remove_feature(Feature, Rest, Reduced).

ablation_report(Guard, Packets, QueryFeatures, FullScore, Feature, Report) :-
    guard_atoms(Guard, Atoms),
    remove_feature(Feature, Atoms, ReducedAtoms),
    guard_from_atoms(ReducedAtoms, ReducedGuard),
    score_guard(ReducedGuard, Packets, QueryFeatures, ReducedScore, ReducedTrace),
    Delta is FullScore - ReducedScore,
    Report = [
        'ContextAblation',
        ['RemovedFeature', Feature],
        ['ReducedGuard', ReducedGuard],
        ReducedTrace,
        ['ScoreDelta', Delta]
    ].

minimality_report(Guard, Packets, QueryFeatures, Report) :-
    score_guard(Guard, Packets, QueryFeatures, FullScore, FullTrace),
    guard_atoms(Guard, Atoms),
    findall(Feature, member(Feature, Atoms), AblationFeatures),
    findall(
        AblationReport,
        (
            member(AblationFeature, AblationFeatures),
            ablation_report(
                Guard,
                Packets,
                QueryFeatures,
                FullScore,
                AblationFeature,
                AblationReport
            )
        ),
        Ablations
    ),
    Report = [
        'ContextMinimalityReport',
        ['FullTrace', FullTrace],
        ['Ablations', Ablations]
    ].

beam_branch_report(MaxDepth, BeamWidth, Branch, Key-Report) :-
    branch_parts(Branch, Name, Statement, Packets, QueryFeatures, Action),
    context_beam_for_query(
        Statement,
        Packets,
        QueryFeatures,
        MaxDepth,
        BeamWidth,
        [
            'ContextBeamAnswer',
            _AnswerStatement,
            Guard,
            Side,
            Evidence,
            Projection,
            Support,
            Trace,
            Beam
        ]
    ),
    trace_score(Trace, Score),
    projection_utility(Projection, Score, Utility),
    Key is -Utility,
    minimality_report(Guard, Packets, QueryFeatures, Minimality),
    Report = [
        'ContextBeamBranchReport',
        Name,
        Statement,
        Action,
        Guard,
        Side,
        Evidence,
        Projection,
        Score,
        Utility,
        Support,
        Trace,
        Minimality,
        Beam
    ].

beam_report_name(['ContextBeamBranchReport', Name|_Rest], Name).
beam_report_action(
    [
        'ContextBeamBranchReport',
        _Name,
        _Statement,
        Action
        |_Rest
    ],
    Action
).

beam_branch_decision(BestName, Report, Decision) :-
    beam_report_name(Report, Name),
    beam_report_action(Report, Action),
    (   Name == BestName
    ->  Decision = ['ContextBranchDecision', execute, Name, Action]
    ;   Decision = ['ContextBranchDecision', prune, Name, Action]
    ).

context_beam_control_for_branches(Branches, MaxDepth0, BeamWidth0, Result) :-
    MaxDepth is round(MaxDepth0),
    BeamWidth is round(BeamWidth0),
    findall(Branch, member(Branch, Branches), BranchItems),
    findall(
        Key-Report,
        (
            member(BranchItem, BranchItems),
            beam_branch_report(MaxDepth, BeamWidth, BranchItem, Key-Report)
        ),
        Pairs
    ),
    keysort(Pairs, SortedPairs),
    findall(Report, member(_Key-Report, SortedPairs), Reports),
    (   Reports = [Best|_Rest]
    ->  beam_report_name(Best, BestName),
        findall(
            Decision,
            (
                member(Report, Reports),
                beam_branch_decision(BestName, Report, Decision)
            ),
            Decisions
        ),
        Result = ['ContextBeamControlResult', Best, Decisions, Reports]
    ;   Result = [
            'ContextBeamControlResult',
            'NoContextBeamBranchReport',
            [],
            []
        ]
    ).
