"""Pure source-foundation orchestration and strict result serialization."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import re
from typing import Any

from . import raw_derivation, path_query, safe_path

CLAIM_CEILING = 'Deterministic canonical-evaluator mechanics over explicitly supplied source evidence and explicitly synthetic fixtures; no native-target feasibility, behavioral usefulness, portability, replacement, default-path, cutover, or production-readiness claim.'
MAX_RESULT_BYTES = 1_420_081
MAX_MARKDOWN_BYTES = 8_520_529
MAX_INVALID_BYTES = 2_846
MAX_REFERENCE_GAPS = 872
MAX_OBLIGATION_GAPS = 32
MAX_GAPS = 968
_DETAILS = {'coherence_assurance', 'pre_assurance', 'post_assurance', 'final_assurance', 'cleanup_assurance'}
_RESULT_FIELDS = set('contract kind authorizing can_execute evidence_mode evidence_basis claim_ceiling input outcome primary_reason reasons relation_results route_results survivors gaps limits replay'.split())


class RawIntakeError(ValueError):
    def __init__(self, *reasons: str) -> None:
        self.reasons = tuple(dict.fromkeys(reasons))
        super().__init__(";".join(self.reasons))


def _adoption_time(value: Any) -> str:
    if not isinstance(value, str):
        raise RawIntakeError("EVIDENCE_TIME")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError
        return timestamp.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
    except (ValueError, OverflowError):
        raise RawIntakeError("EVIDENCE_TIME") from None


class AssessmentResultError(ValueError):
    def __init__(self):
        super().__init__('INVALID_RESULT')


def _digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _measured_limits(invocation):
    return {'input_bytes': len(raw_derivation._json_bytes(invocation)), 'decoded_evidence_bytes': sum(len(row['data'].encode('utf-8')) for row in invocation['artifacts']), 'artifact_count': len(invocation['artifacts']), 'citation_count': len(invocation['citations']), 'relation_count': len(invocation['relations']), 'need_count': len(invocation['needs']), 'approach_count': len(invocation['approaches']), 'limit_hit': invocation['host']['limits']['limit_hit']}


def _reference_gap(reference, properties):
    return {
        'field_path': reference['field_path'],
        'reference_id': reference['reference_id'],
        'properties': sorted(properties),
        'impact': reference['impact'],
    }


def _reference_affected(reference):
    if reference['kind'] == 'citation':
        return ((1, reference['index']),)
    if reference['kind'] == 'candidate':
        return ()
    if reference['kind'] == 'need':
        return ((4, reference['index']),)
    if reference['kind'] == 'approach':
        return ((5, reference['index']),)
    if reference['kind'] == 'relation':
        return ((2, reference['index']),)
    return ()


def _reference_obligations(invocation, citations, artifacts, cache):
    """Return field-located failures and their admitted required contributions."""
    gaps, reasons = [], []
    for reference in raw_derivation._citation_references(invocation):
        identifier = (
            invocation['citations'][reference['index']]['id']
            if reference['kind'] == 'citation'
            else reference['reference_id']
        )
        if identifier not in cache:
            cache[identifier] = path_query._resolve_citation_reference(
                identifier, citations, artifacts,
            )
        fact = cache[identifier]
        properties = _structural_reference_properties(reference, invocation)
        if 'invalid_source_association' in fact['properties']:
            properties.add('invalid_source_association')
        if not properties:
            continue
        gaps.append(_reference_gap(reference, properties))
        if reference['impact'] == 'required_evidence' or reference['impact'] == 'association_integrity':
            reasons.append({
                'code': safe_path.CODES[6],
                'scope': {'kind': 'global'},
                'affected_ids': [
                    list(pair) for pair in _reference_affected(reference)
                ],
                'details': [],
            })
    gaps.sort(key=lambda row: (row['field_path'], row['reference_id']))
    return gaps, reasons


def _structural_reference_properties(reference, invocation):
    """Project namespace edges and declared usability; never inspect bytes."""
    citations = {row['id']: row for row in invocation['citations']}
    artifacts = {row['id']: row for row in invocation['artifacts']}
    if reference['kind'] == 'citation':
        citation = invocation['citations'][reference['index']]
    else:
        citation = citations.get(reference['reference_id'])
    if citation is None:
        return {'missing_citation'}
    artifact = artifacts.get(citation['artifact_id'])
    if artifact is None:
        return {'missing_artifact'}
    properties = set()
    if citation['representation_sha256'] != artifact['representation_sha256']:
        properties.add('invalid_source_association')
    if reference['kind'] != 'citation':
        if 'outside_view' in artifact['limitations']:
            properties.add('outside_view')
        if (set(artifact['limitations']) - {'outside_view'}
                or reference['kind'] == 'relation' and artifact['role'] == 'candidate'):
            properties.add('limited_evidence')
    return properties


def _reference_gap_key(row):
    return row['field_path'], row['reference_id']


def _obligation_gaps(invocation):
    gaps = [
        {
            'approach_id': approach['id'],
            'need_id': assignment['need_id'],
            'property': 'missing_requirement',
        }
        for approach in invocation['approaches']
        for assignment in approach['need_relations']
        if assignment['unresolved'] is not None
    ]
    gaps.sort(key=lambda row: (row['approach_id'], row['need_id']))
    return gaps


def evaluate_assessment(invocation, /):
    admitted, invalid = raw_derivation._admit_assessment(invocation)
    if invalid is not None:
        return invalid
    return _evaluate_admitted_assessment(admitted)


def evaluate_proposal(proposal, capture, /):
    """Pure, non-authorizing evaluation of explicitly supplied proposal and capture data.

    Invalid inputs return the closed invalid-invocation envelope; valid inputs are
    compiled once and their admitted record is evaluated once.
    """
    admitted, invalid = raw_derivation._compile_assessment(proposal, capture)
    if invalid is not None:
        return invalid
    return _evaluate_admitted_assessment(admitted)


def _evaluate_admitted_assessment(invocation):
    codes = safe_path.CODES
    artifacts = {row['id']: row for row in invocation['artifacts']}
    citations = {row['id']: row for row in invocation['citations']}
    host = invocation['host']
    reasons, results, relation_gaps = [], [], []
    citation_cache = {}
    for relation in invocation['relations']:
        result, gap = path_query._evaluate_source_relation(
            relation, citations, artifacts, citation_cache,
        )
        results.append(result)
        if gap is not None:
            relation_gaps.append(gap)
    reference_gaps, reference_reasons = _reference_obligations(
        invocation, citations, artifacts, citation_cache,
    )
    obligation_gaps = _obligation_gaps(invocation)
    reasons.extend(reference_reasons)
    routes, local_reasons, current, current_reasons, metadata_reasons = safe_path._recorded_projection(invocation, results)
    reasons.extend(metadata_reasons)
    for index, artifact in enumerate(invocation['artifacts']):
        data = artifact['data'].encode('utf-8')
        if _digest_bytes(data) != artifact['representation_sha256']:
            reasons.append({'code': codes[6], 'scope': {'kind': 'global'}, 'affected_ids': [[0, index]], 'details': []})
        if artifact['role'] == 'candidate':
            continue
        for other_index, other in enumerate(invocation['artifacts'][:index]):
            if other['role'] == 'candidate':
                continue
            same_identity = all(
                artifact[key] == other[key]
                for key in ('source_identity', 'source_version', 'target_id', 'view_id')
            )
            if ((same_identity and artifact['source_sha256'] != other['source_sha256'])
                    or (artifact['representation_sha256'] == other['representation_sha256']
                        and artifact['data'] != other['data'])):
                reasons.append({'code': codes[7], 'scope': {'kind': 'global'}, 'affected_ids': [[0, other_index], [0, index]], 'details': []})
    reasons.extend(current_reasons)
    proposed = [row['id'] for row in routes if row['state'] == 'supported']
    if not reasons and not local_reasons:
        if current:
            reasons.append({'code': codes[11], 'scope': {'kind': 'global'}, 'affected_ids': [[4, index] for index, need in enumerate(invocation['needs']) if need['load_bearing']], 'details': []})
        else:
            reasons.append({'code': codes[12], 'scope': {'kind': 'global'}, 'affected_ids': [[5, index] for index, route in enumerate(routes) if route['state'] == 'supported'], 'details': []})
    all_reasons = safe_path._merge_reasons(reasons + local_reasons)
    outcome = safe_path._reason_outcome([row['code'] for row in all_reasons])
    origins = {host['origin']} | {row['origin'] for row in invocation['artifacts']}
    mode = 'mixed' if len(origins) > 1 else next(iter(origins))
    relation_gaps.sort(key=lambda row: row['relation_id'])
    result = {'contract': raw_derivation.CONTRACT, 'kind': 'assessment', 'authorizing': False, 'can_execute': False, 'evidence_mode': mode, 'evidence_basis': 'host_attested_unverified', 'claim_ceiling': CLAIM_CEILING, 'input': invocation, 'outcome': outcome, 'primary_reason': all_reasons[0]['code'], 'reasons': all_reasons, 'relation_results': results, 'route_results': routes, 'survivors': proposed if outcome == 'eligible' else [], 'gaps': relation_gaps + reference_gaps + obligation_gaps, 'limits': _measured_limits(invocation), 'replay': {'input_sha256': _digest_bytes(raw_derivation._json_bytes(invocation)), 'status': 'input_result_binding_only'}}
    result['replay']['result_sha256'] = _digest_bytes(raw_derivation._json_bytes(result))
    if len(raw_derivation._json_bytes(result)) > MAX_RESULT_BYTES:
        raise RuntimeError('RESULT_BOUND_EXCEEDED')
    return result


def _require(condition):
    if not condition:
        raise AssessmentResultError()


def _closed(value, fields):
    _require(type(value) is dict and set(value) == set(fields.split()))


def _ordered_ids(values, allowed, maximum):
    _require(type(values) is list and len(values) <= maximum and all(type(item) is str for item in values))
    _require(values == sorted(set(values)) and set(values) <= set(allowed))


def _validate_invalid(result):
    _closed(result, 'contract kind authorizing can_execute primary_diagnostic diagnostics')
    rows = result['diagnostics']
    _require(type(rows) is list and 1 <= len(rows) <= 8)
    keys = []
    for row in rows:
        _closed(row, 'code field_path detail_code')
        _require(type(row['code']) is str and row['code'] in raw_derivation.DIAGNOSTICS)
        for key, maximum in (('code', 64), ('field_path', 128), ('detail_code', 64)):
            _require(type(row[key]) is str and 0 < len(row[key]) <= maximum and row[key].isascii())
        _require(re.fullmatch(r'\$(?:\.[a-z_][a-z0-9_]*|\[(?:[0-9]|[1-5][0-9]|6[0-3])\])*', row['field_path']) is not None)
        _require(re.fullmatch('[A-Z_]+', row['detail_code']) is not None)
        keys.append(raw_derivation.DIAGNOSTICS.index(row['code']))
    _require(keys == sorted(set(keys)) and result['primary_diagnostic'] == rows[0])


def _validate_assessment(result):
    _require(set(result) == _RESULT_FIELDS)
    invocation = result['input']
    _require(not raw_derivation._check_input(invocation))
    _require(invocation == raw_derivation._normalize_input(invocation))
    _require(result['evidence_basis'] == 'host_attested_unverified' and result['claim_ceiling'] == CLAIM_CEILING)
    origins = {invocation['host']['origin']} | {row['origin'] for row in invocation['artifacts']}
    _require(result['evidence_mode'] == ('mixed' if len(origins) > 1 else next(iter(origins))))
    _require(type(result['outcome']) is str and result['outcome'] in {'eligible', 'no_change', 'defer', 'reject', 'needs_more_facts'})
    codes = safe_path.CODES
    relation_ids = [row['id'] for row in invocation['relations']]
    route_ids = [row['id'] for row in invocation['approaches']]
    relation_rows = result['relation_results']
    _require(type(relation_rows) is list and len(relation_rows) == len(relation_ids))
    states = {}
    for source, row in zip(invocation['relations'], relation_rows):
        _closed(row, 'id state citation_ids')
        _require(row['id'] == source['id'] and row['state'] in ('supported', 'contradicted', 'unresolved', 'outside_view'))
        identifiers = [source['left_citation_id'], source['right_citation_id']] if source['kind'] == 'source_same' else [source['citation_id']]
        _require(row['citation_ids'] == sorted(set(identifiers)))
        states[row['id']] = row['state']
    routes = result['route_results']
    _require(type(routes) is list and len(routes) == len(route_ids))
    for source, row in zip(invocation['approaches'], routes):
        _closed(row, 'id state reason_codes relation_ids')
        _require(row['id'] == source['id'] and row['state'] in ('supported', 'omitted'))
        identifiers = sorted({item for assignment in source['need_relations'] for item in assignment['relation_ids']})
        _require(row['relation_ids'] == identifiers and len(identifiers) <= 32)
        _require(type(row['reason_codes']) is list and row['reason_codes'] in ([], [codes[7]], [codes[8]], [codes[7], codes[8]]))
    expected_routes, expected_local, current, current_reasons, metadata_reasons = safe_path._recorded_projection(
        invocation, relation_rows
    )
    _require(routes == expected_routes)
    _ordered_ids(result['survivors'], route_ids, 8)
    supported_ids = sorted(row['id'] for row in routes if row['state'] == 'supported')
    if result['outcome'] == 'eligible':
        _require(result['survivors'] == supported_ids and bool(supported_ids))
    else:
        _require(result['survivors'] == [])
    gaps = result['gaps']
    _require(type(gaps) is list and len(gaps) <= MAX_GAPS)
    relation_gap_ids = []
    reference_rows = []
    obligation_rows = []
    for row in gaps:
        if set(row) == {'relation_id', 'property'}:
            _require(
                row['relation_id'] in states
                and row['property'] in (
                    'false_requirement', 'missing_citation',
                    'limited_evidence', 'outside_view',
                )
            )
            state = states[row['relation_id']]
            _require(state != 'supported')
            _require(row['property'] in {
                'contradicted': ('false_requirement',),
                'unresolved': ('missing_citation', 'limited_evidence'),
                'outside_view': ('outside_view',),
            }[state])
            relation_gap_ids.append(row['relation_id'])
        elif set(row) == {'approach_id', 'need_id', 'property'}:
            _require(
                type(row['approach_id']) is str
                and type(row['need_id']) is str
                and row['property'] == 'missing_requirement'
            )
            obligation_rows.append(row)
        else:
            _closed(row, 'field_path reference_id properties impact')
            _require(
                type(row['field_path']) is str
                and row['field_path'].isascii()
                and 0 < len(row['field_path']) <= 128
                and re.fullmatch(
                    r'\$(?:\.[a-z_][a-z0-9_]*|\[(?:[0-9]|[1-5][0-9]|6[0-3])\])*',
                    row['field_path'],
                ) is not None
            )
            _require(
                type(row['reference_id']) is str
                and re.fullmatch(r'[A-Za-z0-9._:-]{1,32}', row['reference_id']) is not None
            )
            _require(
                type(row['properties']) is list
                and 0 < len(row['properties']) <= 5
                and row['properties'] == sorted(set(row['properties']))
                and set(row['properties']) <= {
                    'missing_citation', 'missing_artifact',
                    'invalid_source_association', 'limited_evidence',
                    'outside_view',
                }
            )
            _require(row['impact'] in {
                'required_evidence', 'optional_provenance',
                'association_integrity',
            })
            reference_rows.append(row)
    _require(
        relation_gap_ids == sorted(
            identifier for identifier, state in states.items() if state != 'supported'
        )
    )
    _require(
        len(relation_gap_ids) <= 64
        and len(reference_rows) <= MAX_REFERENCE_GAPS
        and len(obligation_rows) <= MAX_OBLIGATION_GAPS
    )
    _require(
        reference_rows == sorted(
            reference_rows,
            key=lambda row: (row['field_path'], row['reference_id']),
        )
    )
    _require(
        obligation_rows == sorted(
            obligation_rows,
            key=lambda row: (row['approach_id'], row['need_id']),
        )
    )
    ordered_relation_rows = [
        row for row in gaps if set(row) == {'relation_id', 'property'}
    ]
    _require(gaps == ordered_relation_rows + reference_rows + obligation_rows)
    _require(
        obligation_rows == _obligation_gaps(invocation)
    )
    references = list(raw_derivation._citation_references(invocation))
    reference_map = {
        (row['field_path'], row['reference_id']): row
        for row in references
    }
    actual_reference_map = {}
    for row in reference_rows:
        key = _reference_gap_key(row)
        _require(key in reference_map and key not in actual_reference_map)
        expected = reference_map[key]
        _require(row['impact'] == expected['impact'])
        actual_reference_map[key] = row
    # One recorded association observation must agree across all citation uses.
    # Its byte-level truth is not independently re-proved here.
    invalid_associations = set()
    for reference in references:
        key = (reference['field_path'], reference['reference_id'])
        row = actual_reference_map.get(key)
        if row is not None and 'invalid_source_association' in row['properties']:
            identifier = (
                invocation['citations'][reference['index']]['id']
                if reference['kind'] == 'citation' else reference['reference_id']
            )
            invalid_associations.add(identifier)
    for reference in references:
        expected_properties = _structural_reference_properties(reference, invocation)
        key = (reference['field_path'], reference['reference_id'])
        row = actual_reference_map.get(key)
        identifier = (
            invocation['citations'][reference['index']]['id']
            if reference['kind'] == 'citation' else reference['reference_id']
        )
        if not expected_properties & {'missing_citation', 'missing_artifact'}:
            if identifier in invalid_associations:
                expected_properties.add('invalid_source_association')
        _require((set(row['properties']) if row is not None else set()) == expected_properties)
    references_by_relation = {}
    for reference in references:
        if reference['kind'] != 'relation':
            continue
        key = (reference['field_path'], reference['reference_id'])
        references_by_relation.setdefault(reference['index'], []).append(
            set(actual_reference_map[key]['properties'])
            if key in actual_reference_map else set()
        )
    for relation_index, properties_rows in references_by_relation.items():
        properties = set().union(*properties_rows)
        if not properties:
            continue
        relation = invocation['relations'][relation_index]
        state = states[relation['id']]
        if {'missing_citation', 'missing_artifact'} & properties:
            expected_state, expected_gap = 'unresolved', 'missing_citation'
        elif 'outside_view' in properties:
            expected_state, expected_gap = 'outside_view', 'outside_view'
        else:
            expected_state, expected_gap = 'unresolved', 'limited_evidence'
        _require(state == expected_state)
        _require({
            gap['relation_id']: gap['property']
            for gap in gaps
            if set(gap) == {'relation_id', 'property'}
        }.get(relation['id']) == expected_gap)
    for relation_index, relation in enumerate(invocation['relations']):
        state = states[relation['id']]
        if state not in {'unresolved', 'outside_view'}:
            continue
        _require(any(
            reference['kind'] == 'relation'
            and reference['index'] == relation_index
            and (reference['field_path'], reference['reference_id'])
            in actual_reference_map
            for reference in references
        ))
    namespaces = [invocation['artifacts'], invocation['citations'], invocation['relations'], invocation['view']['descriptors'], invocation['needs'], invocation['approaches'], invocation['view']['root_ids'], invocation['components']]
    reasons = result['reasons']
    _require(type(reasons) is list and 1 <= len(reasons) <= 29)
    keys = []
    for row in reasons:
        _closed(row, 'code scope affected_ids details')
        _require(type(row['code']) is str and row['code'] in codes)
        scope = row['scope']
        _require(type(scope) is dict)
        if scope.get('kind') == 'global':
            _closed(scope, 'kind')
        elif scope.get('kind') == 'approach':
            _closed(scope, 'kind id')
            _require(type(scope['id']) is str and scope['id'] in route_ids and row['code'] in codes[7:9])
        else:
            raise AssessmentResultError()
        keys.append(safe_path._reason_key(row))
        pairs = row['affected_ids']
        _require(type(pairs) is list and len(pairs) <= 172)
        for pair in pairs:
            _require(type(pair) is list and len(pair) == 2 and all(type(part) is int for part in pair))
            _require(0 <= pair[0] < 8 and 0 <= pair[1] < len(namespaces[pair[0]]))
        _require(pairs == [list(pair) for pair in sorted(set(map(tuple, pairs)))])
        _ordered_ids(row['details'], _DETAILS, 5)
        _require(not row['details'] or scope == {'kind': 'global'} and row['code'] == codes[2])
    _require(keys == sorted(set(keys)) and result['primary_reason'] == reasons[0]['code'])

    def merged_rows(rows):
        return {
            (row['code'], tuple(sorted(row['scope'].items()))): row
            for row in safe_path._merge_reasons(rows)
        }

    actual = merged_rows(reasons)
    expected_local = merged_rows(expected_local)
    actual_local = {
        key: row for key, row in actual.items()
        if row['scope']['kind'] == 'approach'
    }
    _require(actual_local == expected_local)

    expected_reference_reasons = []
    for reference in references:
        key = (reference['field_path'], reference['reference_id'])
        field_gap = actual_reference_map.get(key)
        if field_gap is None:
            continue
        if reference['impact'] not in {'required_evidence', 'association_integrity'}:
            continue
        expected_reference_reasons.append({
            'code': codes[6],
            'scope': {'kind': 'global'},
            'affected_ids': [
                list(pair)
                for pair in _reference_affected(reference)
            ],
            'details': [],
        })
    expected_global = merged_rows(
        current_reasons + metadata_reasons + expected_reference_reasons
    )
    primitive_namespaces = {
        codes[6]: {0},     # R7: artifact observations; citations have reference gaps.
        codes[7]: {0},     # R8: captured artifact identity observations.
    }
    global_keys = {
        key for key, row in actual.items() if row['scope']['kind'] == 'global'
        and row['code'] not in (codes[11], codes[12])
    }
    for key, expected in expected_global.items():
        actual_row = actual.get(key)
        _require(actual_row is not None)
        expected_pairs = set(map(tuple, expected['affected_ids']))
        actual_pairs = set(map(tuple, actual_row['affected_ids']))
        allowed_extra = {
            pair for pair in actual_pairs - expected_pairs
            if expected['code'] in primitive_namespaces
            and pair[0] in primitive_namespaces[expected['code']]
        }
        _require(actual_pairs <= expected_pairs | allowed_extra)
        _require(expected_pairs <= actual_pairs)
        _require(actual_row['details'] == expected['details'])
        global_keys.discard(key)
    for key in global_keys:
        row = actual[key]
        _require(row['code'] in primitive_namespaces)
        _require(row['affected_ids'])
        _require(all(
            pair[0] in primitive_namespaces[row['code']]
            for pair in row['affected_ids']
        ))

    reason_codes = [row['code'] for row in reasons]
    _require(safe_path._reason_outcome(reason_codes) == result['outcome'])
    positive = {codes[11], codes[12]} & set(reason_codes)
    if positive:
        _require(len(reason_codes) == 1)
        expected_code = codes[11] if current else codes[12]
        _require(reason_codes == [expected_code])
        expected_affected = (
            [[4, index] for index, need in enumerate(invocation['needs']) if need['load_bearing']]
            if current else
            [[5, index] for index, route in enumerate(routes) if route['state'] == 'supported']
        )
        _require(reasons[0]['affected_ids'] == expected_affected)
    expected_limits = _measured_limits(invocation)
    _closed(result['limits'], 'input_bytes decoded_evidence_bytes artifact_count citation_count relation_count need_count approach_count limit_hit')
    for key, value in expected_limits.items():
        _require(type(result['limits'][key]) is type(value) and result['limits'][key] == value)
    _closed(result['replay'], 'input_sha256 result_sha256 status')
    _require(result['replay']['status'] == 'input_result_binding_only')
    for key in ('input_sha256', 'result_sha256'):
        _require(type(result['replay'][key]) is str and re.fullmatch('[0-9a-f]{64}', result['replay'][key]) is not None)
    _require(result['replay']['input_sha256'] == _digest_bytes(raw_derivation._json_bytes(invocation)))
    unsigned = copy.deepcopy(result)
    del unsigned['replay']['result_sha256']
    _require(result['replay']['result_sha256'] == _digest_bytes(raw_derivation._json_bytes(unsigned)))


def canonical_result_bytes(result, /):
    """Validate recorded relationships and bindings without fresh evidence assessment."""
    try:
        checks = raw_derivation._Checks()
        _require(raw_derivation._domain(result, checks))
        _require(type(result) is dict and result.get('contract') == raw_derivation.CONTRACT)
        _require(result.get('authorizing') is False and result.get('can_execute') is False)
        if result.get('kind') == 'invalid_invocation':
            _validate_invalid(result)
            bound = MAX_INVALID_BYTES
        elif result.get('kind') == 'assessment':
            _validate_assessment(result)
            bound = MAX_RESULT_BYTES
        else:
            raise AssessmentResultError()
        encoded = raw_derivation._json_bytes(result)
        _require(len(encoded) <= bound)
        return encoded
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise AssessmentResultError() from None
