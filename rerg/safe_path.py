"""Unranked route filtering and the single charter reason algebra."""
CODES = (
    'TARGET_IDENTITY_MISMATCH', 'READ_SCOPE_MISMATCH_OR_ESCAPE',
    'SNAPSHOT_STALE_OR_CHANGED', 'ADMITTED_VIEW_MISSING_FILE',
    'RESOURCE_LIMIT_REACHED', 'COVERAGE_INCOMPLETE',
    'CITATION_OR_HASH_COVERAGE_INSUFFICIENT', 'TARGET_EVIDENCE_CONTRADICTORY',
    'LOAD_BEARING_NEED_UNRESOLVED', 'REJECT_UNSUPPORTED_UNSAFE_OR_DISALLOWED',
    'DEFER_POLICY_OR_NOT_READY', 'NO_CHANGE_CURRENT_SURFACE_SUFFICIENT',
    'ELIGIBLE_COVERAGE_CONFIRMED',
)


def _reason_outcome(codes):
    values = set(codes)
    if not values or not values <= set(CODES):
        raise ValueError('INVALID_REASON_SET')
    if values.intersection((CODES[0], CODES[1], CODES[9])):
        return 'reject'
    if len(values) > 1 and values.intersection(CODES[10:]):
        return 'needs_more_facts'
    if values.intersection(CODES[2:9]):
        return 'needs_more_facts'
    if CODES[10] in values:
        return 'defer'
    if CODES[11] in values:
        return 'no_change'
    return 'eligible'


def _scope_key(scope):
    if scope['kind'] == 'global':
        return (0, '')
    return (1, scope['id'])


def _reason_key(row):
    """Canonical order: reason precedence, then tagged scope and identifier."""
    return (CODES.index(row['code']), *_scope_key(row['scope']))


def _merge_reasons(rows):
    merged = {}
    for row in rows:
        key = _reason_key(row)
        if key not in merged:
            merged[key] = {
                'code': row['code'],
                'scope': dict(row['scope']),
                'affected_ids': set(),
                'details': set(),
            }
        merged[key]['affected_ids'].update(tuple(pair) for pair in row['affected_ids'])
        merged[key]['details'].update(row['details'])
    return [
        {
            'code': row['code'],
            'scope': row['scope'],
            'affected_ids': [list(pair) for pair in sorted(row['affected_ids'])],
            'details': sorted(row['details']),
        }
        for _, row in sorted(merged.items())
    ]


def _reason_row(code, scope, affected=(), details=()):
    return {
        'code': CODES[code] if isinstance(code, int) else code,
        'scope': dict(scope),
        'affected_ids': [list(pair) for pair in affected],
        'details': list(details),
    }


def _state_code(state):
    return CODES[7] if state == 'contradicted' else CODES[8]


def _assess_routes(invocation, relation_results):
    """Project route state and required-use contributions from recorded states."""
    relations = {row['id']: row for row in relation_results}
    relation_indexes = {row['id']: index for index, row in enumerate(invocation['relations'])}
    needs = {row['id']: row for row in invocation['needs']}
    routes, reasons = [], []
    need_indexes = {row['id']: index for index, row in enumerate(invocation['needs'])}
    for index, approach in enumerate(invocation['approaches']):
        supported = True
        codes = set()
        identifiers = set()
        for assignment in approach['need_relations']:
            need = needs[assignment['need_id']]
            if assignment['unresolved'] is not None:
                codes.add(CODES[8])
                if need['load_bearing']:
                    supported = False
                    reasons.append(_reason_row(
                        CODES[8],
                        {'kind': 'approach', 'id': approach['id']},
                        (
                            (4, need_indexes[assignment['need_id']]),
                            (5, index),
                        ),
                    ))
            for identifier in assignment['relation_ids']:
                identifiers.add(identifier)
                state = relations[identifier]['state']
                if state == 'supported':
                    continue
                code = _state_code(state)
                codes.add(code)
                if need['load_bearing']:
                    supported = False
                    reasons.append(_reason_row(
                        code,
                        {'kind': 'approach', 'id': approach['id']},
                        ((2, relation_indexes[identifier]), (5, index)),
                    ))
        routes.append({
            'id': approach['id'],
            'state': 'supported' if supported else 'omitted',
            'reason_codes': sorted(codes, key=CODES.index),
            'relation_ids': sorted(identifiers),
        })
    return routes, reasons


def _current_projection(invocation, relation_results):
    """Return current-surface sufficiency and its required global contributions."""
    relations = {row['id']: row for row in relation_results}
    relation_indexes = {row['id']: index for index, row in enumerate(invocation['relations'])}
    reasons = []
    load_bearing = []
    complete = True
    for need_index, need in enumerate(invocation['needs']):
        if not need['load_bearing']:
            continue
        load_bearing.append(need)
        if not need['current_relation_ids']:
            complete = False
        for identifier in need['current_relation_ids']:
            state = relations[identifier]['state']
            if state == 'supported':
                continue
            complete = False
            reasons.append(_reason_row(
                _state_code(state),
                {'kind': 'global'},
                ((2, relation_indexes[identifier]), (4, need_index)),
            ))
    return bool(load_bearing) and complete, reasons


def _metadata_reasons(invocation, routes, current):
    """Project global reasons that are decidable from declared packet metadata."""
    host, view, target = invocation['host'], invocation['view'], invocation['target']
    reasons = []
    def add(number, affected=(), details=()):
        reasons.append(_reason_row(number - 1, {'kind': 'global'}, affected, details))

    if target != host['target_binding'] or view['target_id'] != target['id']:
        add(1)
    if (set(view['root_ids']) != set(host['root_ids'])
            or view['operation'] != host['operation']
            or host['view_id'] != view['id']):
        add(2)
    details = ([] if host['coherence'] == 'immutable' else ['coherence_assurance']) + [
        field + '_assurance' for field in ('pre', 'post', 'final', 'cleanup')
        if host['checks'][field] != 'pass'
    ]
    if details:
        add(3, details=details)
    associated = []
    if not view['descriptors']:
        add(6)
    artifacts = {row['id']: row for row in invocation['artifacts']}
    for index, descriptor in enumerate(view['descriptors']):
        refs = ((3, index),)
        if descriptor['root_id'] not in view['root_ids']:
            add(2, refs)
        if (descriptor['state'] == 'missing'
                or descriptor['state'] == 'inspected' and descriptor['artifact_id'] not in artifacts):
            add(4, refs)
        if descriptor['state'] != 'inspected':
            add(6, refs)
        if descriptor['artifact_id'] is not None:
            if descriptor['artifact_id'] in associated:
                prior = tuple((3, i) for i, row in enumerate(view['descriptors'][:index])
                              if row['artifact_id'] == descriptor['artifact_id'])
                add(6, prior + refs)
            associated.append(descriptor['artifact_id'])
    for index, artifact in enumerate(invocation['artifacts']):
        if artifact['role'] == 'candidate':
            continue
        if artifact['target_id'] != target['id']:
            add(1, ((0, index),))
        if artifact['view_id'] != view['id']:
            add(2, ((0, index),))
        if artifact['id'] not in associated:
            add(6, ((0, index),))
    if host['limits']['limit_hit']:
        add(5)
    decoded = sum(len(row['data'].encode('utf-8')) for row in invocation['artifacts'])
    if (host['limits']['decoded_bytes'] != decoded
            or host['limits']['artifact_count'] != len(artifacts)):
        add(6)
    load_bearing = [row for row in invocation['needs'] if row['load_bearing']]
    proposed = [row for row in routes if row['state'] == 'supported']
    if (not load_bearing or (not current and not proposed)
            or target['configuration_digest'] is None):
        add(9)
    if not host['policy']['allowed']:
        add(10)
    if not host['policy']['ready']:
        add(11)
    return reasons


def _recorded_projection(invocation, relation_results):
    """Shared route/current/metadata projection for evaluation and publication."""
    routes, route_reasons = _assess_routes(invocation, relation_results)
    current, current_reasons = _current_projection(invocation, relation_results)
    metadata_reasons = _metadata_reasons(invocation, routes, current)
    return routes, route_reasons, current, current_reasons, metadata_reasons
