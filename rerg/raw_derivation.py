"""Closed, effect-free admission of explicitly supplied foundation evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

CONTRACT = 'rerg-foundation/3'
DIAGNOSTICS = ('INVALID_ENCODING_OR_SIZE', 'UNSUPPORTED_CONTRACT', 'MISSING_REQUIRED_FIELD', 'DUPLICATE_FIELD', 'AMBIGUOUS_TARGET_DECLARATION', 'MALFORMED_TARGET_OR_SNAPSHOT', 'UNSAFE_HANDOFF_OR_SCOPE_DESCRIPTOR', 'INVALID_FIELD_VALUE')
COMPONENTS = tuple('rerg/' + name + '.py' for name in ('__init__', '__main__', 'raw_cli', 'raw_intake', 'raw_derivation', 'path_query', 'safe_path', 'render'))
_DEFERRED = {'absence', 'identity', 'exact_version', 'event_ordering', 'transition', 'preservation', 'change', 'provenance', 'coverage', 'contradiction', 'boundedness', 'validation'}
_TOP = 'contract candidate target view host artifacts citations relations needs approaches components'
_NARRATIVES = 'mechanism required_changes constraints dependencies risks unknowns validation reversibility stop_conditions'

# These constants are shared by the machine-visible tool schema below and the
# procedural admission path.  Keep the two paths mechanically aligned: the
# schema rejects malformed wire shapes before dispatch, while admission still
# owns cross-record and evidence semantics.
IDENTIFIER_PATTERN = r'^[A-Za-z0-9._:-]{1,32}$'
DIGEST_PATTERN = r'^[0-9a-f]{64}$'
MAX_TEXT_LENGTH = 512
MAX_UNRESOLVED_BYTES = 512
MAX_DATA_LENGTH = 4096
SOURCE_KINDS = ('url', 'repository', 'note', 'specification', 'question')
OPERATIONS = ('read_supplied_bytes',)
VIEW_STATES = ('inspected', 'missing', 'excluded', 'failed', 'unsupported')
SURFACES = ('installed_runtime', 'repository_snapshot', 'other_source')
ORIGINS = ('synthetic', 'supplied_source')
EVIDENCE_BASES = ('host_attested_unverified',)
COHERENCE_STATES = ('immutable', 'changed', 'unknown')
CHECK_STATES = ('pass', 'fail', 'unknown')
ARTIFACT_ROLES = ('candidate', 'source', 'configuration')
ARTIFACT_LIMITATIONS = ('redacted', 'truncated', 'extraction_failed', 'unsupported', 'outside_view')
RELATION_KINDS = ('source_present', 'source_equals', 'source_same')
LOCAL_KEY_PATTERN = r'^[A-Za-z0-9._:-]{1,24}$'
ASSESSMENT_CONTRACT = 'rerg-assessment-request/1'
ASSESSMENT_NARRATIVES = _NARRATIVES.split()
MISSING_REQUIREMENT_MARKER = 'Missing requirement declaration.'
LOCAL_PATH_POLICY = 'local_only_not_portable_or_publication_safe'
_LOCAL_PATH_RE = re.compile(r'(?i)/(?:home|Users)/')
_PRIVATE_KEY_RE = re.compile(r'-----BEGIN [^\n]*PRIVATE KEY-----', re.IGNORECASE)
_CREDENTIAL_NAME = r'(?:github[_-]?token|aws[_-]?(?:(?:secret[_-])?access[_-]?key(?:[_-]?id)?|session[_-]?token)|api[_-]?key|private[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|refresh[_-]?token|id[_-]?token|password|passwd|secret|token|authorization)'
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    rf'''(?ix)(?<![A-Za-z0-9_])["']?(?P<key>{_CREDENTIAL_NAME})["']?\s*\]?\s*[:=]\s*(?P<value>"[^"\r\n]+"|'[^'\r\n]+'|[^\s"']+)'''
)
_QUERY_CREDENTIAL_RE = re.compile(
    r'(?i)[?&](?:api[_-]?key|private[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|refresh[_-]?token|id[_-]?token|token|password|passwd|secret)='
)
_AUTHORIZATION_BEARER_RE = re.compile(
    r'''(?i)\bauthorization\b["']?\s*\]?\s*[:=]\s*["']?bearer\s+[A-Za-z0-9._~+/-=]+'''
)
_BEARER_RE = re.compile(r'(?i)\bbearer\s+["\']?\S+')
_URL_USERINFO_RE = re.compile(r'''(?i)(?:\b[a-z][a-z0-9+.-]*:)?//[^\s/?#@]*@''')
_PERCENT_BYTES_RE = re.compile(r'(?:%[0-9a-fA-F]{2})+')


def _ref(name):
    return {'$ref': f'#/$defs/{name}'}


def _text_schema(
    *,
    empty=False,
    canonical_maximum=MAX_TEXT_LENGTH,
    utf8_maximum=None,
):
    schema = {
        'type': 'string',
        'minLength': 0 if empty else 1,
        # JSON Schema counts code points, not encoded bytes.  This is the
        # strongest standard bound that cannot reject a value admitted by the
        # byte limits below; exact byte enforcement remains in admission.
        'maxLength': min(
            canonical_maximum - 2,
            utf8_maximum if utf8_maximum is not None else canonical_maximum - 2,
        ),
        'x-maxCanonicalJsonBytes': canonical_maximum,
    }
    if utf8_maximum is not None:
        schema['x-maxUtf8Bytes'] = utf8_maximum
    return schema


def _array_schema(items, *, maximum, minimum=0, unique=False):
    schema = {
        'type': 'array',
        'items': items,
        'minItems': minimum,
        'maxItems': maximum,
    }
    if unique:
        schema['uniqueItems'] = True
    return schema


def _object_schema(properties, required):
    return {
        'type': 'object',
        'additionalProperties': False,
        'required': list(required),
        'properties': properties,
    }


def _build_invocation_schema():
    """Return the complete closed JSON Schema for one foundation invocation."""
    identifier = {
        'type': 'string',
        'minLength': 1,
        'maxLength': 32,
        'pattern': IDENTIFIER_PATTERN,
    }
    digest = {'type': 'string', 'pattern': DIGEST_PATTERN, 'minLength': 64, 'maxLength': 64}
    nullable_digest = {
        'type': ['string', 'null'],
        'pattern': DIGEST_PATTERN,
        'minLength': 64,
        'maxLength': 64,
    }
    integer = {'type': 'integer', 'minimum': 0, 'maximum': 2**63 - 1}
    nullable_integer = {
        'type': ['integer', 'null'],
        'minimum': 0,
        'maximum': 2**63 - 1,
    }
    narrative = _object_schema(
        {
            'text': _text_schema(),
            'citation_ids': _array_schema(_ref('identifier'), maximum=8, unique=True),
        },
        ('text', 'citation_ids'),
    )
    target = _object_schema(
        {
            'id': _ref('identifier'),
            'harness': _text_schema(),
            'version': _text_schema(),
            'surface': {'type': 'string', 'enum': list(SURFACES)},
            'configuration_digest': nullable_digest,
        },
        ('id', 'harness', 'version', 'surface', 'configuration_digest'),
    )
    descriptor = _object_schema(
        {
            'id': _ref('identifier'),
            'root_id': _ref('identifier'),
            'artifact_id': {'anyOf': [_ref('identifier'), {'type': 'null'}]},
            'state': {'type': 'string', 'enum': list(VIEW_STATES)},
        },
        ('id', 'root_id', 'artifact_id', 'state'),
    )
    host = _object_schema(
        {
            'origin': {'type': 'string', 'enum': list(ORIGINS)},
            'evidence_basis': {'type': 'string', 'enum': list(EVIDENCE_BASES)},
            'grant_id': _ref('identifier'),
            'target_binding': _ref('target'),
            'local_path_policy': {'type': 'string', 'const': LOCAL_PATH_POLICY},
            'view_id': _ref('identifier'),
            'root_ids': _array_schema(_ref('identifier'), maximum=8, minimum=1, unique=True),
            'operation': {'type': 'string', 'enum': list(OPERATIONS)},
            'coherence': {'type': 'string', 'enum': list(COHERENCE_STATES)},
            'checks': _object_schema(
                {name: {'type': 'string', 'enum': list(CHECK_STATES)}
                 for name in ('pre', 'post', 'final', 'cleanup')},
                ('pre', 'post', 'final', 'cleanup'),
            ),
            'policy': _object_schema(
                {'allowed': {'type': 'boolean'}, 'ready': {'type': 'boolean'}},
                ('allowed', 'ready'),
            ),
            'limits': _object_schema(
                {
                    'decoded_bytes': integer,
                    'artifact_count': integer,
                    'limit_hit': {'type': 'boolean'},
                },
                ('decoded_bytes', 'artifact_count', 'limit_hit'),
            ),
        },
        (
            'origin', 'evidence_basis', 'grant_id', 'target_binding', 'view_id',
            'root_ids', 'operation', 'coherence', 'checks', 'policy', 'limits',
        ),
    )
    host['allOf'] = [
        {
            'if': {'properties': {'origin': {'const': 'synthetic'}}},
            'then': {'properties': {'grant_id': {'pattern': r'^syn:'}}},
        },
        {
            'if': {'properties': {'origin': {'const': 'supplied_source'}}},
            'then': {'properties': {'grant_id': {'not': {'pattern': r'^syn:'}}}},
        },
    ]
    artifact = _object_schema(
        {
            'id': _ref('identifier'),
            'origin': {'type': 'string', 'enum': list(ORIGINS)},
            'role': {'type': 'string', 'enum': list(ARTIFACT_ROLES)},
            'target_id': _ref('identifier'),
            'view_id': _ref('identifier'),
            'source_identity': _text_schema(),
            'source_version': _text_schema(),
            'source_sha256': _ref('digest'),
            'representation_sha256': _ref('digest'),
            'data': _text_schema(
                empty=True,
                canonical_maximum=24578,
                utf8_maximum=MAX_DATA_LENGTH,
            ),
            'limitations': _array_schema(
                {'type': 'string', 'enum': list(ARTIFACT_LIMITATIONS)},
                maximum=5,
                unique=True,
            ),
        },
        (
            'id', 'origin', 'role', 'target_id', 'view_id', 'source_identity',
            'source_version', 'source_sha256', 'representation_sha256', 'data',
            'limitations',
        ),
    )
    artifact['allOf'] = [
        {
            'if': {'properties': {'origin': {'const': 'synthetic'}}},
            'then': {'properties': {'id': {'pattern': r'^syn:'}}},
        },
        {
            'if': {'properties': {'origin': {'const': 'supplied_source'}}},
            'then': {'properties': {'id': {'not': {'pattern': r'^syn:'}}}},
        },
    ]
    citation = _object_schema(
        {
            'id': _ref('identifier'),
            'artifact_id': _ref('identifier'),
            'representation_sha256': _ref('digest'),
            'start_byte': integer,
            'end_byte': integer,
        },
        ('id', 'artifact_id', 'representation_sha256', 'start_byte', 'end_byte'),
    )
    relation_present = _object_schema(
        {
            'id': _ref('identifier'),
            'kind': {'const': 'source_present', 'enum': ['source_present']},
            'citation_id': _ref('identifier'),
        },
        ('id', 'kind', 'citation_id'),
    )
    relation_equals = _object_schema(
        {
            'id': _ref('identifier'),
            'kind': {'const': 'source_equals', 'enum': ['source_equals']},
            'citation_id': _ref('identifier'),
            'expected': _text_schema(),
        },
        ('id', 'kind', 'citation_id', 'expected'),
    )
    relation_same = _object_schema(
        {
            'id': _ref('identifier'),
            'kind': {'const': 'source_same', 'enum': ['source_same']},
            'left_citation_id': _ref('identifier'),
            'right_citation_id': _ref('identifier'),
        },
        ('id', 'kind', 'left_citation_id', 'right_citation_id'),
    )
    need = _object_schema(
        {
            'id': _ref('identifier'),
            'statement': _text_schema(),
            'citation_ids': _array_schema(_ref('identifier'), maximum=8, unique=True),
            'load_bearing': {'type': 'boolean'},
            'current_relation_ids': _array_schema(_ref('identifier'), maximum=8, unique=True),
        },
        ('id', 'statement', 'citation_ids', 'load_bearing', 'current_relation_ids'),
    )
    need_relation = _object_schema(
        {
            'need_id': _ref('identifier'),
            'relation_ids': _array_schema(_ref('identifier'), maximum=8, unique=True),
            'unresolved': {
                'anyOf': [
                    {'type': 'null'},
                    _text_schema(canonical_maximum=MAX_UNRESOLVED_BYTES),
                ],
            },
        },
        ('need_id', 'relation_ids', 'unresolved'),
    )
    approach = _object_schema(
        {
            'id': _ref('identifier'),
            'need_relations': _array_schema(_ref('need_relation'), maximum=4),
            'lift': _object_schema(
                {
                    'amount': nullable_integer,
                    'unit': _text_schema(),
                    'basis': _ref('narrative'),
                },
                ('amount', 'unit', 'basis'),
            ),
            **{name: _ref('narrative') for name in _NARRATIVES.split()},
        },
        ('id', 'need_relations', 'lift', *_NARRATIVES.split()),
    )
    component = _object_schema(
        {'path': {'type': 'string', 'enum': list(COMPONENTS)}, 'sha256': _ref('digest')},
        ('path', 'sha256'),
    )
    definitions = {
        'identifier': identifier,
        'digest': digest,
        'narrative': narrative,
        'target': target,
        'descriptor': descriptor,
        'host': host,
        'artifact': artifact,
        'citation': citation,
        'relation_present': relation_present,
        'relation_equals': relation_equals,
        'relation_same': relation_same,
        'need': need,
        'need_relation': need_relation,
        'approach': approach,
        'component': component,
    }
    return {
        'type': 'object',
        'additionalProperties': False,
        'required': _TOP.split(),
        'properties': {
            'contract': {'const': CONTRACT, 'enum': [CONTRACT]},
            'candidate': _object_schema(
                {
                    'id': _ref('identifier'),
                    'source_kind': {'type': 'string', 'enum': list(SOURCE_KINDS)},
                    'locator': _text_schema(),
                    'question': _text_schema(),
                    'citation_ids': _array_schema(_ref('identifier'), maximum=8, unique=True),
                },
                ('id', 'source_kind', 'locator', 'question', 'citation_ids'),
            ),
            'target': _ref('target'),
            'view': _object_schema(
                {
                    'id': _ref('identifier'),
                    'target_id': _ref('identifier'),
                    'root_ids': _array_schema(_ref('identifier'), maximum=8, minimum=1, unique=True),
                    'operation': {'type': 'string', 'enum': list(OPERATIONS)},
                    'descriptors': _array_schema(_ref('descriptor'), maximum=8),
                },
                ('id', 'target_id', 'root_ids', 'operation', 'descriptors'),
            ),
            'host': _ref('host'),
            'artifacts': _array_schema(_ref('artifact'), maximum=8),
            'citations': _array_schema(_ref('citation'), maximum=64),
            'relations': _array_schema(
                {
                    'oneOf': [
                        _ref('relation_present'),
                        _ref('relation_equals'),
                        _ref('relation_same'),
                    ],
                },
                maximum=64,
            ),
            'needs': _array_schema(_ref('need'), maximum=4),
            'approaches': _array_schema(_ref('approach'), maximum=8),
            'components': _array_schema(_ref('component'), maximum=8, minimum=8),
        },
        '$defs': definitions,
    }


INVOCATION_SCHEMA = _build_invocation_schema()


def _build_assessment_schema():
    """Return the closed high-level request schema.

    The schema is deliberately structural.  Cross-record references, byte
    spans and the generated low-level packet remain the compiler's job.
    """
    local_key = {
        'type': 'string', 'minLength': 1, 'maxLength': 24,
        'pattern': LOCAL_KEY_PATTERN,
    }
    digest = {'type': 'string', 'minLength': 64, 'maxLength': 64, 'pattern': DIGEST_PATTERN}
    integer = {'type': 'integer', 'minimum': 0, 'maximum': 2**63 - 1}
    nullable_digest = {'type': ['string', 'null'], 'minLength': 64, 'maxLength': 64, 'pattern': DIGEST_PATTERN}
    span = _object_schema(
        {'artifact_key': local_key, 'start_byte': integer, 'end_byte': integer},
        ('artifact_key', 'start_byte', 'end_byte'),
    )
    present = _object_schema(
        {'kind': {'const': 'source_present', 'enum': ['source_present']}, 'span': _ref('assessment_span')},
        ('kind', 'span'),
    )
    equals = _object_schema(
        {'kind': {'const': 'source_equals', 'enum': ['source_equals']}, 'span': _ref('assessment_span'), 'expected': _text_schema()},
        ('kind', 'span', 'expected'),
    )
    same = _object_schema(
        {'kind': {'const': 'source_same', 'enum': ['source_same']}, 'left': _ref('assessment_span'), 'right': _ref('assessment_span')},
        ('kind', 'left', 'right'),
    )
    requirement = {
        'oneOf': [_ref('assessment_requirement_present'), _ref('assessment_requirement_equals'), _ref('assessment_requirement_same')],
    }
    narrative = _object_schema(
        {'text': _text_schema(), 'citations': _array_schema(_ref('assessment_span'), maximum=8)},
        ('text', 'citations'),
    )
    target = _object_schema(
        {
            'key': local_key, 'harness': _text_schema(), 'version': _text_schema(),
            'surface': {'type': 'string', 'enum': list(SURFACES)},
            'configuration_digest': nullable_digest,
        },
        ('key', 'harness', 'version', 'surface', 'configuration_digest'),
    )
    candidate = _object_schema(
        {'key': local_key, 'source_kind': {'type': 'string', 'enum': list(SOURCE_KINDS)}, 'locator': _text_schema(), 'question': _text_schema(), 'citations': _array_schema(_ref('assessment_span'), maximum=8)},
        ('key', 'source_kind', 'locator', 'question', 'citations'),
    )
    need = _object_schema(
        {
            'key': local_key, 'statement': _text_schema(),
            'citations': _array_schema(_ref('assessment_span'), maximum=8),
            'load_bearing': {'type': 'boolean'},
            'current_requirements': {'type': ['array', 'null'], 'items': requirement, 'maxItems': 8},
        },
        ('key', 'statement', 'citations', 'load_bearing', 'current_requirements'),
    )
    coverage = _object_schema(
        {
            'need_key': local_key,
            'requirements': {'type': ['array', 'null'], 'items': requirement, 'maxItems': 8},
            'unresolved': {'type': ['string', 'null'], 'maxLength': 510},
        },
        ('need_key', 'requirements', 'unresolved'),
    )
    approach = _object_schema(
        {
            'key': local_key,
            'coverage': _array_schema(coverage, maximum=4),
            'lift': _object_schema(
                {
                    'amount': {'type': ['integer', 'null'], 'minimum': 0, 'maximum': 2**63 - 1},
                    'unit': _text_schema(),
                    'basis': _ref('assessment_narrative'),
                },
                ('amount', 'unit', 'basis'),
            ),
            **{name: _ref('assessment_narrative') for name in ASSESSMENT_NARRATIVES},
        },
        ('key', 'coverage', 'lift', *ASSESSMENT_NARRATIVES),
    )
    descriptor = _object_schema(
        {'key': local_key, 'root_key': local_key, 'artifact_key': {'type': ['string', 'null'], 'pattern': LOCAL_KEY_PATTERN, 'minLength': 1, 'maxLength': 24}, 'state': {'type': 'string', 'enum': list(VIEW_STATES)}},
        ('key', 'root_key', 'artifact_key', 'state'),
    )
    view = _object_schema(
        {'key': local_key, 'target_key': local_key, 'root_keys': _array_schema(local_key, maximum=8, minimum=1), 'operation': {'type': 'string', 'enum': list(OPERATIONS)}, 'descriptors': _array_schema(_ref('assessment_descriptor'), maximum=8)},
        ('key', 'target_key', 'root_keys', 'operation', 'descriptors'),
    )
    host = _object_schema(
        {
            'origin': {'type': 'string', 'enum': list(ORIGINS)},
            'evidence_basis': {'type': 'string', 'enum': list(EVIDENCE_BASES)},
            'grant_id': {'type': 'string', 'minLength': 1, 'maxLength': 32, 'pattern': IDENTIFIER_PATTERN},
            'local_path_policy': {'type': 'string', 'const': LOCAL_PATH_POLICY},
            'view_key': local_key,
            'root_keys': _array_schema(local_key, maximum=8, minimum=1),
            'operation': {'type': 'string', 'enum': list(OPERATIONS)},
            'coherence': {'type': 'string', 'enum': list(COHERENCE_STATES)},
            'checks': _object_schema({name: {'type': 'string', 'enum': list(CHECK_STATES)} for name in ('pre', 'post', 'final', 'cleanup')}, ('pre', 'post', 'final', 'cleanup')),
            'policy': _object_schema({'allowed': {'type': 'boolean'}, 'ready': {'type': 'boolean'}}, ('allowed', 'ready')),
            'limits': _object_schema({'limit_hit': {'type': 'boolean'}}, ('limit_hit',)),
        },
        ('origin', 'evidence_basis', 'grant_id', 'view_key', 'root_keys', 'operation', 'coherence', 'checks', 'policy', 'limits'),
    )
    artifact = _object_schema(
        {
            'key': local_key, 'origin': {'type': 'string', 'enum': list(ORIGINS)},
            'role': {'type': 'string', 'enum': list(ARTIFACT_ROLES)},
            'target_key': local_key, 'view_key': local_key,
            'source_identity': _text_schema(), 'source_version': _text_schema(),
            'source_sha256': digest, 'data': _text_schema(empty=True, canonical_maximum=24578, utf8_maximum=MAX_DATA_LENGTH),
            'limitations': _array_schema({'type': 'string', 'enum': list(ARTIFACT_LIMITATIONS)}, maximum=5),
        },
        ('key', 'origin', 'role', 'target_key', 'view_key', 'source_identity', 'source_version', 'source_sha256', 'data', 'limitations'),
    )
    component = _object_schema({'path': {'type': 'string', 'enum': list(COMPONENTS)}, 'sha256': digest}, ('path', 'sha256'))
    definitions = {
        'assessment_span': span,
        'assessment_requirement_present': present,
        'assessment_requirement_equals': equals,
        'assessment_requirement_same': same,
        'assessment_narrative': narrative,
        'assessment_requirement': requirement,
        'assessment_descriptor': descriptor,
    }
    return {
        'type': 'object',
        'additionalProperties': False,
        'required': ['proposal', 'capture'],
        'properties': {
            'proposal': _object_schema(
                {
                    'contract': {'const': ASSESSMENT_CONTRACT, 'enum': [ASSESSMENT_CONTRACT]},
                    'candidate': _ref('assessment_candidate'),
                    'target': _ref('assessment_target'),
                    'needs': _array_schema(_ref('assessment_need'), maximum=4),
                    'approaches': _array_schema(_ref('assessment_approach'), maximum=8),
                },
                ('contract', 'candidate', 'target', 'needs', 'approaches'),
            ),
            'capture': _object_schema(
                {
                    'target': _ref('assessment_target'),
                    'view': _ref('assessment_view'),
                    'host': _ref('assessment_host'),
                    'artifacts': _array_schema(_ref('assessment_artifact'), maximum=8),
                    'components': _array_schema(_ref('assessment_component'), maximum=8, minimum=8),
                },
                ('target', 'view', 'host', 'artifacts', 'components'),
            ),
        },
        '$defs': {
            **definitions,
            'assessment_candidate': candidate,
            'assessment_target': target,
            'assessment_need': need,
            'assessment_coverage': coverage,
            'assessment_approach': approach,
            'assessment_view': view,
            'assessment_host': host,
            'assessment_artifact': artifact,
            'assessment_component': component,
        },
    }


ASSESSMENT_SCHEMA = _build_assessment_schema()


def _citation_references(invocation):
    """Enumerate every declared citation edge and its derived impact."""
    required_relations = {
        relation_id
        for need in invocation['needs']
        if need['load_bearing']
        for relation_id in need['current_relation_ids']
    }
    needs = {need['id']: need for need in invocation['needs']}
    for approach in invocation['approaches']:
        for assignment in approach['need_relations']:
            if needs[assignment['need_id']]['load_bearing']:
                required_relations.update(assignment['relation_ids'])

    def emit(field_path, reference_id, impact, *, kind, index):
        yield {
            'field_path': field_path,
            'reference_id': reference_id,
            'impact': impact,
            'kind': kind,
            'index': index,
        }

    for index, reference_id in enumerate(invocation['candidate']['citation_ids']):
        yield from emit(
            f'$.candidate.citation_ids[{index}]', reference_id,
            'optional_provenance', kind='candidate', index=None,
        )
    for index, need in enumerate(invocation['needs']):
        impact = 'required_evidence' if need['load_bearing'] else 'optional_provenance'
        for citation_index, reference_id in enumerate(need['citation_ids']):
            yield from emit(
                f'$.needs[{index}].citation_ids[{citation_index}]',
                reference_id, impact, kind='need', index=index,
            )
    for index, relation in enumerate(invocation['relations']):
        identifiers = (
            ('left_citation_id', relation['left_citation_id']),
            ('right_citation_id', relation['right_citation_id']),
        ) if relation['kind'] == 'source_same' else (
            ('citation_id', relation['citation_id']),
        )
        impact = (
            'required_evidence' if relation['id'] in required_relations
            else 'optional_provenance'
        )
        for field, reference_id in identifiers:
            yield from emit(
                f'$.relations[{index}].{field}', reference_id, impact,
                kind='relation', index=index,
            )
    for index, approach in enumerate(invocation['approaches']):
        for field in _NARRATIVES.split():
            for citation_index, reference_id in enumerate(approach[field]['citation_ids']):
                yield from emit(
                    f'$.approaches[{index}].{field}.citation_ids[{citation_index}]',
                    reference_id, 'optional_provenance', kind='approach', index=index,
                )
        for citation_index, reference_id in enumerate(approach['lift']['basis']['citation_ids']):
            yield from emit(
                f'$.approaches[{index}].lift.basis.citation_ids[{citation_index}]',
                reference_id, 'optional_provenance', kind='approach', index=index,
            )
    for index, citation in enumerate(invocation['citations']):
        yield from emit(
            f'$.citations[{index}].artifact_id', citation['artifact_id'],
            'association_integrity', kind='citation', index=index,
        )


class EnvelopeValidationError(ValueError):
    def __init__(self, *reasons: str) -> None:
        self.reasons = tuple(dict.fromkeys(reasons))
        super().__init__(";".join(self.reasons))


def _text(value: Any, *, empty: bool = False, allow_local_paths: bool = False) -> None:
    if type(value) is not str or (not empty and not value) or len(value) > 1_048_576:
        raise EnvelopeValidationError("EVIDENCE_TEXT")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise EnvelopeValidationError("EVIDENCE_TEXT") from None
    if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
        raise EnvelopeValidationError("UNSAFE_EVIDENCE")
    if (not allow_local_paths and _LOCAL_PATH_RE.search(value)) or _contains_secret(value):
        raise EnvelopeValidationError("UNSAFE_EVIDENCE")


def _contains_secret(value):
    """Reject credential-bearing text, checking decoded forms without rewriting."""
    for text in (value, _percent_decode(value)):
        if (
            _PRIVATE_KEY_RE.search(text)
            or _QUERY_CREDENTIAL_RE.search(text)
            or _AUTHORIZATION_BEARER_RE.search(text)
            or _BEARER_RE.search(text)
            or _URL_USERINFO_RE.search(text)
        ):
            return True
        if _CREDENTIAL_ASSIGNMENT_RE.search(text):
            return True
    return False


def _percent_decode(value):
    """Decode percent bytes like unquote while leaving literal Unicode intact."""
    return _PERCENT_BYTES_RE.sub(
        lambda match: bytes.fromhex(match.group().replace('%', '')).decode('utf-8', errors='replace'),
        value,
    )


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _invalid(diagnostics):
    representatives = {}
    for code, path, detail in diagnostics:
        candidate = (path, detail)
        if code not in representatives or candidate < representatives[code]:
            representatives[code] = candidate
    rows = [{'code': code, 'field_path': representatives[code][0], 'detail_code': representatives[code][1]} for code in DIAGNOSTICS if code in representatives]
    if not rows:
        raise ValueError('EMPTY_DIAGNOSTICS')
    return {'contract': CONTRACT, 'kind': 'invalid_invocation', 'authorizing': False, 'can_execute': False, 'primary_diagnostic': rows[0].copy(), 'diagnostics': rows}


class _Checks:
    """Collect safe schema diagnostics without echoing arbitrary input paths."""
    def __init__(self):
        self.errors = []

    def fail(self, path, detail='INVALID_FIELD_VALUE', code='INVALID_FIELD_VALUE'):
        self.errors.append((code, path, detail))

    def shape(self, value, fields, path, *, optional=()):
        if type(value) is not dict:
            self.fail(path, 'INVALID_FIELD_VALUE')
            return False
        wanted = set(fields.split())
        allowed = wanted | set(optional)
        for key in sorted(wanted - value.keys()):
            self.fail(path + '.' + key, 'MISSING_REQUIRED_FIELD', 'MISSING_REQUIRED_FIELD')
        for key in value.keys() - allowed:
            safe = path + '.kind' if path == '$' and key == 'kind' else path
            self.fail(safe, 'EXTRA_FIELD')
        return wanted <= value.keys()

    def text(self, value, path, maximum=512, empty=False, *, allow_local_paths=False):
        if type(value) is not str:
            self.fail(path, 'INVALID_FIELD_VALUE')
            return False
        try:
            _text(value, empty=empty, allow_local_paths=allow_local_paths)
        except EnvelopeValidationError as error:
            code = 'UNSAFE_HANDOFF_OR_SCOPE_DESCRIPTOR' if 'UNSAFE_EVIDENCE' in error.reasons else 'INVALID_FIELD_VALUE'
            self.fail(path, code, code)
            return False
        if len(_json_bytes(value)) > maximum:
            self.fail(path, 'INVALID_ENCODING_OR_SIZE', 'INVALID_ENCODING_OR_SIZE')
            return False
        return True

    def identifier(self, value, path):
        if type(value) is not str or re.fullmatch(IDENTIFIER_PATTERN, value) is None:
            self.fail(path, 'INVALID_FIELD_VALUE')
            return False
        return True

    def digest(self, value, path, nullable=False):
        if value is None and nullable:
            return
        if type(value) is not str or re.fullmatch(DIGEST_PATTERN, value) is None:
            self.fail(path, 'DIGEST_INVALID')

    def integer(self, value, path, nullable=False):
        if value is None and nullable:
            return
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            self.fail(path, 'INVALID_FIELD_VALUE')

    def boolean(self, value, path):
        if type(value) is not bool:
            self.fail(path, 'INVALID_FIELD_VALUE')

    def enum(self, value, allowed, path, deferred=()):
        if type(value) is str and value in deferred:
            self.fail(path, 'RELATION_REDUCTION_UNSUPPORTED', 'UNSUPPORTED_CONTRACT')
        elif type(value) is not str or value not in allowed:
            self.fail(path, 'ENUM_INVALID')

    def sequence(self, value, path, maximum, minimum=0):
        if type(value) is not list:
            self.fail(path, 'INVALID_FIELD_VALUE')
            return []
        if not minimum <= len(value) <= maximum:
            self.fail(path, 'INVALID_ENCODING_OR_SIZE', 'INVALID_ENCODING_OR_SIZE')
            return []
        return value

    def ids(self, value, path, maximum=8, minimum=0):
        values = self.sequence(value, path, maximum, minimum)
        valid = True
        for index, item in enumerate(values):
            valid = self.identifier(item, f'{path}[{index}]') and valid
        if valid and len(set(values)) != len(values):
            self.fail(path, 'INVALID_FIELD_VALUE')
        return values

    def records(self, value, path, maximum, key='id'):
        values = self.sequence(value, path, maximum)
        seen = set()
        result = []
        for index, item in enumerate(values):
            at = f'{path}[{index}]'
            if type(item) is not dict:
                self.fail(at, 'INVALID_FIELD_VALUE')
                continue
            if key not in item:
                self.fail(at + '.' + key, 'MISSING_REQUIRED_FIELD', 'MISSING_REQUIRED_FIELD')
            elif self.identifier(item[key], at + '.' + key):
                if item[key] in seen:
                    self.fail(at + '.' + key, 'INVALID_FIELD_VALUE')
                seen.add(item[key])
            result.append((item, at))
        return result

    def narrative(self, value, path):
        if self.shape(value, 'text citation_ids', path):
            self.text(value['text'], path + '.text')
            self.ids(value['citation_ids'], path + '.citation_ids')

    def target(self, value, path, *, allow_local_paths=False):
        if self.shape(value, 'id harness version surface configuration_digest', path):
            self.identifier(value['id'], path + '.id')
            self.text(value['harness'], path + '.harness', allow_local_paths=allow_local_paths)
            self.text(value['version'], path + '.version')
            self.enum(value['surface'], SURFACES, path + '.surface')
            self.digest(value['configuration_digest'], path + '.configuration_digest', True)


def _local_paths_enabled(host, path, checks):
    if type(host) is not dict or 'local_path_policy' not in host:
        return False
    policy = host['local_path_policy']
    checks.enum(policy, (LOCAL_PATH_POLICY,), path + '.local_path_policy')
    return type(policy) is str and policy == LOCAL_PATH_POLICY


def _domain(value, checks, path='$', ancestors=None, depth=0):
    if ancestors is None:
        ancestors = set()
    if depth > 32:
        checks.fail(path, 'INVALID_ENCODING_OR_SIZE', 'INVALID_ENCODING_OR_SIZE')
        return False
    kind = type(value)
    if kind in (dict, list):
        identity = id(value)
        if identity in ancestors:
            checks.fail(path, 'INVALID_FIELD_VALUE')
            return False
        ancestors.add(identity)
        valid = True
        children = value.values() if kind is dict else value
        if kind is dict and any(type(key) is not str for key in value):
            checks.fail(path, 'INVALID_FIELD_VALUE')
            valid = False
        if kind is dict:
            for key in value:
                if type(key) is str:
                    valid = _domain(key, checks, path, ancestors, depth + 1) and valid
        for child in children:
            valid = _domain(child, checks, path, ancestors, depth + 1) and valid
        ancestors.remove(identity)
        return valid
    if kind is str:
        try:
            value.encode('utf-8')
        except UnicodeError:
            checks.fail(path, 'INVALID_ENCODING_OR_SIZE', 'INVALID_ENCODING_OR_SIZE')
            return False
        return True
    if value is None or kind is bool or (kind is int and -(2**63) <= value < 2**63):
        return True
    checks.fail(path, 'INVALID_FIELD_VALUE')
    return False


def _check_input(value):
    c = _Checks()
    if not _domain(value, c):
        return c.errors
    if len(_json_bytes(value)) > 1_048_576:
        c.fail('$', 'INVALID_ENCODING_OR_SIZE', 'INVALID_ENCODING_OR_SIZE')
        return c.errors
    if not c.shape(value, _TOP, '$'):
        return c.errors
    if value['contract'] != CONTRACT:
        c.fail('$.contract', 'VERSION_UNSUPPORTED', 'UNSUPPORTED_CONTRACT')
        return c.errors
    host = value['host']
    allow_local_paths = _local_paths_enabled(host, '$.host', c)
    candidate = value['candidate']
    if c.shape(candidate, 'id source_kind locator question citation_ids', '$.candidate'):
        c.identifier(candidate['id'], '$.candidate.id')
        c.enum(candidate['source_kind'], SOURCE_KINDS, '$.candidate.source_kind')
        for field in ('locator', 'question'):
            c.text(candidate[field], '$.candidate.' + field)
        c.ids(candidate['citation_ids'], '$.candidate.citation_ids')
    c.target(value['target'], '$.target', allow_local_paths=allow_local_paths)
    view = value['view']
    if c.shape(view, 'id target_id root_ids operation descriptors', '$.view'):
        for field in ('id', 'target_id'):
            c.identifier(view[field], '$.view.' + field)
        c.ids(view['root_ids'], '$.view.root_ids', minimum=1)
        c.enum(view['operation'], OPERATIONS, '$.view.operation')
        for row, path in c.records(view['descriptors'], '$.view.descriptors', 8):
            if c.shape(row, 'id root_id artifact_id state', path):
                c.identifier(row['root_id'], path + '.root_id')
                if row['artifact_id'] is not None:
                    c.identifier(row['artifact_id'], path + '.artifact_id')
                c.enum(row['state'], VIEW_STATES, path + '.state')
    if c.shape(
        host,
        'origin evidence_basis grant_id target_binding view_id root_ids operation coherence checks policy limits',
        '$.host',
        optional=('local_path_policy',),
    ):
        c.enum(host['origin'], ORIGINS, '$.host.origin')
        c.enum(host['evidence_basis'], EVIDENCE_BASES, '$.host.evidence_basis')
        if c.identifier(host['grant_id'], '$.host.grant_id') and host['origin'] in ('synthetic', 'supplied_source'):
            if host['grant_id'].startswith('syn:') != (host['origin'] == 'synthetic'):
                c.fail('$.host.grant_id', 'INVALID_FIELD_VALUE')
        c.target(
            host['target_binding'], '$.host.target_binding',
            allow_local_paths=allow_local_paths,
        )
        c.identifier(host['view_id'], '$.host.view_id')
        c.ids(host['root_ids'], '$.host.root_ids', minimum=1)
        c.enum(host['operation'], OPERATIONS, '$.host.operation')
        c.enum(host['coherence'], COHERENCE_STATES, '$.host.coherence')
        if c.shape(host['checks'], 'pre post final cleanup', '$.host.checks'):
            for field in ('pre', 'post', 'final', 'cleanup'):
                c.enum(host['checks'][field], CHECK_STATES, '$.host.checks.' + field)
        if c.shape(host['policy'], 'allowed ready', '$.host.policy'):
            for field in ('allowed', 'ready'):
                c.boolean(host['policy'][field], '$.host.policy.' + field)
        if c.shape(host['limits'], 'decoded_bytes artifact_count limit_hit', '$.host.limits'):
            for field in ('decoded_bytes', 'artifact_count'):
                c.integer(host['limits'][field], '$.host.limits.' + field)
            c.boolean(host['limits']['limit_hit'], '$.host.limits.limit_hit')
    for row, path in c.records(value['artifacts'], '$.artifacts', 8):
        if not c.shape(row, 'id origin role target_id view_id source_identity source_version source_sha256 representation_sha256 data limitations', path):
            continue
        c.enum(row['origin'], ORIGINS, path + '.origin')
        c.enum(row['role'], ARTIFACT_ROLES, path + '.role', {'runtime', 'validation', 'policy'})
        if type(row.get('id')) is str and row['origin'] in ('synthetic', 'supplied_source') and row['id'].startswith('syn:') != (row['origin'] == 'synthetic'):
            c.fail(path + '.id', 'INVALID_FIELD_VALUE')
        for field in ('target_id', 'view_id'):
            c.identifier(row[field], path + '.' + field)
        c.text(
            row['source_identity'], path + '.source_identity',
            allow_local_paths=allow_local_paths,
        )
        c.text(row['source_version'], path + '.source_version')
        for field in ('source_sha256', 'representation_sha256'):
            c.digest(row[field], path + '.' + field)
        if c.text(
            row['data'], path + '.data', 24578, True,
            allow_local_paths=allow_local_paths,
        ) and len(row['data'].encode('utf-8')) > 4096:
            c.fail(path + '.data', 'INVALID_ENCODING_OR_SIZE', 'INVALID_ENCODING_OR_SIZE')
        limitations = c.ids(row['limitations'], path + '.limitations', 5)
        for item in limitations:
            c.enum(item, ARTIFACT_LIMITATIONS, path + '.limitations')
    for row, path in c.records(value['citations'], '$.citations', 64):
        if c.shape(row, 'id artifact_id representation_sha256 start_byte end_byte', path):
            c.identifier(row['artifact_id'], path + '.artifact_id')
            c.digest(row['representation_sha256'], path + '.representation_sha256')
            for field in ('start_byte', 'end_byte'):
                c.integer(row[field], path + '.' + field)
            if type(row['start_byte']) is int and type(row['end_byte']) is int and row['start_byte'] >= row['end_byte']:
                c.fail(path, 'INVALID_FIELD_VALUE')
    for row, path in c.records(value['relations'], '$.relations', 64):
        kind = row.get('kind')
        if kind not in RELATION_KINDS:
            if 'kind' not in row:
                c.fail(path + '.kind', 'MISSING_REQUIRED_FIELD', 'MISSING_REQUIRED_FIELD')
            else:
                c.enum(kind, RELATION_KINDS, path + '.kind', _DEFERRED)
            continue
        fields = 'id kind left_citation_id right_citation_id' if kind == 'source_same' else 'id kind citation_id' + (' expected' if kind == 'source_equals' else '')
        if c.shape(row, fields, path):
            for field in (('left_citation_id', 'right_citation_id') if kind == 'source_same' else ('citation_id',)):
                c.identifier(row[field], path + '.' + field)
            if kind == 'source_equals':
                c.text(row['expected'], path + '.expected')
    for row, path in c.records(value['needs'], '$.needs', 4):
        if c.shape(row, 'id statement citation_ids load_bearing current_relation_ids', path):
            c.text(row['statement'], path + '.statement')
            c.ids(row['citation_ids'], path + '.citation_ids')
            c.boolean(row['load_bearing'], path + '.load_bearing')
            c.ids(row['current_relation_ids'], path + '.current_relation_ids')
    for row, path in c.records(value['approaches'], '$.approaches', 8):
        if not c.shape(row, 'id need_relations lift ' + _NARRATIVES, path):
            continue
        for field in _NARRATIVES.split():
            c.narrative(row[field], path + '.' + field)
        if c.shape(row['lift'], 'amount unit basis', path + '.lift'):
            c.integer(row['lift']['amount'], path + '.lift.amount', True)
            c.text(row['lift']['unit'], path + '.lift.unit')
            c.narrative(row['lift']['basis'], path + '.lift.basis')
        for relation, at in c.records(row['need_relations'], path + '.need_relations', 4, 'need_id'):
            if c.shape(relation, 'need_id relation_ids unresolved', at):
                c.ids(relation['relation_ids'], at + '.relation_ids')
                if relation['unresolved'] is not None:
                    c.text(
                        relation['unresolved'],
                        at + '.unresolved',
                        MAX_UNRESOLVED_BYTES,
                    )
    components = c.sequence(value['components'], '$.components', 8)
    component_paths = []
    for index, row in enumerate(components):
        path = f'$.components[{index}]'
        if c.shape(row, 'path sha256', path):
            if type(row['path']) is not str or row['path'] not in COMPONENTS:
                c.fail(path + '.path', 'COMPONENT_PATH')
            c.digest(row['sha256'], path + '.sha256')
            component_paths.append(row['path'])
    if all(type(path) is str for path in component_paths):
        if len(set(component_paths)) != len(component_paths):
            c.fail('$.components', 'COMPONENT_DUPLICATE', 'DUPLICATE_FIELD')
        if type(value['components']) is list and len(value['components']) < 8:
            c.fail('$.components', 'COMPONENT_MISSING', 'MISSING_REQUIRED_FIELD')
    if not c.errors:
        relation_ids = {row['id'] for row in value['relations']}
        needs = {row['id']: row for row in value['needs']}
        for index, need in enumerate(value['needs']):
            if not set(need['current_relation_ids']) <= relation_ids:
                c.fail(f'$.needs[{index}].current_relation_ids', 'INVALID_FIELD_VALUE')
        for index, approach in enumerate(value['approaches']):
            assigned = {row['need_id']: row for row in approach['need_relations']}
            if set(assigned) != set(needs):
                c.fail(f'$.approaches[{index}].need_relations', 'INVALID_FIELD_VALUE')
            for assignment in approach['need_relations']:
                need = needs.get(assignment['need_id'])
                if not set(assignment['relation_ids']) <= relation_ids or (
                    need and need['load_bearing']
                    and not assignment['relation_ids']
                    and assignment['unresolved'] is None
                ):
                    c.fail(f'$.approaches[{index}].need_relations', 'INVALID_FIELD_VALUE')
    return c.errors


def _normalize_input(value):
    result = copy.deepcopy(value)
    for field in ('artifacts', 'citations', 'relations', 'needs', 'approaches'):
        result[field].sort(key=lambda row: row['id'])
    result['components'].sort(key=lambda row: row['path'])
    result['view']['descriptors'].sort(key=lambda row: row['id'])
    for owner in (result['host'], result['view']):
        owner['root_ids'].sort()
    result['candidate']['citation_ids'].sort()
    for artifact in result['artifacts']:
        artifact['limitations'].sort()
    for need in result['needs']:
        need['citation_ids'].sort()
        need['current_relation_ids'].sort()
    for approach in result['approaches']:
        approach['need_relations'].sort(key=lambda row: row['need_id'])
        for item in approach['need_relations']:
            item['relation_ids'].sort()
        for field in _NARRATIVES.split():
            approach[field]['citation_ids'].sort()
        approach['lift']['basis']['citation_ids'].sort()
    return result


def _admit_assessment(invocation, *, diagnostic_paths=None):
    errors = _check_input(invocation)
    if errors:
        if diagnostic_paths is not None:
            mapped = []
            for code, path, detail in errors:
                source_path = None
                if isinstance(diagnostic_paths, dict):
                    candidates = [
                        (key, value) for key, value in diagnostic_paths.items()
                        if path == key or path.startswith(key + '.')
                        or path.startswith(key + '[')
                    ]
                    if candidates:
                        source_path = max(candidates, key=lambda item: len(item[0]))[1]
                if source_path is None:
                    if path == '$':
                        source_path = '$.proposal'
                    else:
                        raise _InternalCompilerFailure('UNMAPPABLE_DIAGNOSTIC')
                mapped.append((code, source_path, detail))
            errors = mapped
        return None, _invalid(errors)
    return _normalize_input(invocation), None


class _InternalCompilerFailure(RuntimeError):
    """Raised when a compiler invariant cannot be mapped to supplied input."""


def _local_key(value, path, checks):
    if type(value) is not str or re.fullmatch(LOCAL_KEY_PATTERN, value) is None:
        checks.fail(path, 'INVALID_FIELD_VALUE')
        return False
    return True


def _request_span(value, path, checks):
    if not checks.shape(value, 'artifact_key start_byte end_byte', path):
        return None
    _local_key(value['artifact_key'], path + '.artifact_key', checks)
    checks.integer(value['start_byte'], path + '.start_byte')
    checks.integer(value['end_byte'], path + '.end_byte')
    if (
        type(value['start_byte']) is int and type(value['end_byte']) is int
        and value['start_byte'] >= value['end_byte']
    ):
        checks.fail(path, 'SPAN_ORDER_INVALID')
    return value


def _request_spans(value, path, checks):
    values = checks.sequence(value, path, 8)
    for index, span in enumerate(values):
        _request_span(span, f'{path}[{index}]', checks)
    return values


def _request_local_ids(value, path, checks, *, maximum=8, minimum=0):
    values = checks.sequence(value, path, maximum, minimum)
    valid = True
    for index, item in enumerate(values):
        valid = _local_key(item, f'{path}[{index}]', checks) and valid
    if valid and len(values) != len(set(values)):
        checks.fail(path, 'DUPLICATE_KEY', 'DUPLICATE_FIELD')
    return values


def _request_requirement(value, path, checks):
    if type(value) is not dict:
        checks.fail(path, 'INVALID_FIELD_VALUE')
        return None
    kind = value.get('kind')
    if kind not in RELATION_KINDS:
        if 'kind' not in value:
            checks.fail(path + '.kind', 'MISSING_REQUIRED_FIELD', 'MISSING_REQUIRED_FIELD')
        else:
            checks.fail(path + '.kind', 'UNSUPPORTED_REQUIREMENT_KIND', 'UNSUPPORTED_CONTRACT')
        return None
    fields = (
        'kind span' if kind == 'source_present'
        else 'kind span expected' if kind == 'source_equals'
        else 'kind left right'
    )
    if not checks.shape(value, fields, path):
        return None
    if kind in ('source_present', 'source_equals'):
        _request_span(value['span'], path + '.span', checks)
    else:
        _request_span(value['left'], path + '.left', checks)
        _request_span(value['right'], path + '.right', checks)
    if kind == 'source_equals':
        checks.text(value['expected'], path + '.expected')
    return value


def _request_requirements(value, path, checks):
    if value is None:
        return None
    values = checks.sequence(value, path, 8)
    for index, requirement in enumerate(values):
        _request_requirement(requirement, f'{path}[{index}]', checks)
    return values


def _request_narrative(value, path, checks):
    if not checks.shape(value, 'text citations', path):
        return
    checks.text(value['text'], path + '.text')
    _request_spans(value['citations'], path + '.citations', checks)


def _request_target(value, path, checks, *, allow_local_paths=False):
    if not checks.shape(value, 'key harness version surface configuration_digest', path):
        return
    _local_key(value['key'], path + '.key', checks)
    checks.text(value['harness'], path + '.harness', allow_local_paths=allow_local_paths)
    checks.text(value['version'], path + '.version')
    checks.enum(value['surface'], SURFACES, path + '.surface')
    checks.digest(value['configuration_digest'], path + '.configuration_digest', True)


def _request_check_input(value):
    """Validate the high-level shape before any generated record exists."""
    checks = _Checks()
    if not _domain(value, checks):
        return checks.errors
    try:
        if len(_json_bytes(value)) > 1_048_576:
            checks.fail('$', 'INVALID_ENCODING_OR_SIZE', 'INVALID_ENCODING_OR_SIZE')
            return checks.errors
    except (TypeError, ValueError, OverflowError):
        checks.fail('$', 'INVALID_ENCODING_OR_SIZE', 'INVALID_ENCODING_OR_SIZE')
        return checks.errors
    if not checks.shape(value, 'proposal capture', '$'):
        return checks.errors
    proposal, capture = value.get('proposal'), value.get('capture')
    if not checks.shape(capture, 'target view host artifacts components', '$.capture'):
        return checks.errors
    host = capture.get('host')
    allow_local_paths = _local_paths_enabled(host, '$.capture.host', checks)
    if not checks.shape(proposal, 'contract candidate target needs approaches', '$.proposal'):
        return checks.errors
    if proposal.get('contract') != ASSESSMENT_CONTRACT:
        checks.fail('$.proposal.contract', 'VERSION_UNSUPPORTED', 'UNSUPPORTED_CONTRACT')
    candidate = proposal.get('candidate')
    if checks.shape(candidate, 'key source_kind locator question citations', '$.proposal.candidate'):
        _local_key(candidate['key'], '$.proposal.candidate.key', checks)
        checks.enum(candidate['source_kind'], SOURCE_KINDS, '$.proposal.candidate.source_kind')
        checks.text(candidate['locator'], '$.proposal.candidate.locator')
        checks.text(candidate['question'], '$.proposal.candidate.question')
        _request_spans(candidate['citations'], '$.proposal.candidate.citations', checks)
    _request_target(
        proposal.get('target'), '$.proposal.target', checks,
        allow_local_paths=allow_local_paths,
    )
    needs = checks.sequence(proposal.get('needs'), '$.proposal.needs', 4)
    need_keys = set()
    invalid_need_keys = set()
    load_bearing_need_keys = set()
    for index, need in enumerate(needs):
        path = f'$.proposal.needs[{index}]'
        if not checks.shape(need, 'key statement citations load_bearing current_requirements', path):
            continue
        if _local_key(need['key'], path + '.key', checks):
            first_need_key = need['key'] not in need_keys
            if not first_need_key:
                checks.fail(path + '.key', 'DUPLICATE_KEY', 'DUPLICATE_FIELD')
            need_keys.add(need['key'])
            if (
                first_need_key
                and type(need['load_bearing']) is bool
                and need['load_bearing']
            ):
                load_bearing_need_keys.add(need['key'])
        elif type(need.get('key')) is str:
            invalid_need_keys.add(need['key'])
        checks.text(need['statement'], path + '.statement')
        _request_spans(need['citations'], path + '.citations', checks)
        checks.boolean(need['load_bearing'], path + '.load_bearing')
        requirements = _request_requirements(need['current_requirements'], path + '.current_requirements', checks)
        # Explicit [] compiles to empty current relations (honest incomplete
        # current); only null remains malformed for load-bearing needs.
        if (
            type(need['load_bearing']) is bool and need['load_bearing']
            and requirements is None
        ):
            checks.fail(path + '.current_requirements', 'REQUIRED_REQUIREMENTS_EMPTY')
    approaches = checks.sequence(proposal.get('approaches'), '$.proposal.approaches', 8)
    approach_keys = set()
    for index, approach in enumerate(approaches):
        path = f'$.proposal.approaches[{index}]'
        if not checks.shape(approach, 'key coverage lift ' + ' '.join(ASSESSMENT_NARRATIVES), path):
            continue
        if _local_key(approach['key'], path + '.key', checks):
            if approach['key'] in approach_keys:
                checks.fail(path + '.key', 'DUPLICATE_KEY', 'DUPLICATE_FIELD')
            approach_keys.add(approach['key'])
        coverage = checks.sequence(approach['coverage'], path + '.coverage', 4)
        coverage_keys = set()
        for coverage_index, row in enumerate(coverage):
            at = f'{path}.coverage[{coverage_index}]'
            if not checks.shape(row, 'need_key requirements unresolved', at):
                continue
            need_key_valid = _local_key(row['need_key'], at + '.need_key', checks)
            if need_key_valid:
                if row['need_key'] in coverage_keys:
                    checks.fail(at + '.need_key', 'DUPLICATE_COVERAGE', 'DUPLICATE_FIELD')
                coverage_keys.add(row['need_key'])
                if row['need_key'] not in need_keys and row['need_key'] not in invalid_need_keys:
                    checks.fail(at + '.need_key', 'REFERENCE_INVALID')
            requirements = _request_requirements(row['requirements'], at + '.requirements', checks)
            # Explicit []/null coverage is admitted only with a valid nonempty
            # unresolved obligation; empty without unresolved stays malformed.
            # Omitted coverage rows compile to MISSING_REQUIREMENT_MARKER elsewhere.
            unresolved_value = row.get('unresolved')
            has_unresolved = type(unresolved_value) is str and unresolved_value != ''
            if (
                need_key_valid and row['need_key'] in need_keys
                and
                (requirements is None or not requirements)
                and row['need_key'] in load_bearing_need_keys
                and not has_unresolved
            ):
                checks.fail(at + '.requirements', 'REQUIRED_REQUIREMENTS_EMPTY')
            if row['unresolved'] is not None:
                checks.text(row['unresolved'], at + '.unresolved', MAX_UNRESOLVED_BYTES)
                if type(row['unresolved']) is str and not row['unresolved']:
                    checks.fail(at + '.unresolved', 'INVALID_FIELD_VALUE')
        for field in ASSESSMENT_NARRATIVES:
            _request_narrative(approach.get(field), path + '.' + field, checks)
        lift = approach.get('lift')
        if checks.shape(lift, 'amount unit basis', path + '.lift'):
            checks.integer(lift['amount'], path + '.lift.amount', True)
            checks.text(lift['unit'], path + '.lift.unit')
            _request_narrative(lift['basis'], path + '.lift.basis', checks)
    _request_target(
        capture.get('target'), '$.capture.target', checks,
        allow_local_paths=allow_local_paths,
    )
    view = capture.get('view')
    if checks.shape(view, 'key target_key root_keys operation descriptors', '$.capture.view'):
        _local_key(view['key'], '$.capture.view.key', checks)
        _local_key(view['target_key'], '$.capture.view.target_key', checks)
        _request_local_ids(view['root_keys'], '$.capture.view.root_keys', checks, minimum=1)
        checks.enum(view['operation'], OPERATIONS, '$.capture.view.operation')
        descriptors = checks.sequence(view['descriptors'], '$.capture.view.descriptors', 8)
        descriptor_keys = set()
        for index, row in enumerate(descriptors):
            path = f'$.capture.view.descriptors[{index}]'
            if not checks.shape(row, 'key root_key artifact_key state', path):
                continue
            if _local_key(row['key'], path + '.key', checks):
                if row['key'] in descriptor_keys:
                    checks.fail(path + '.key', 'DUPLICATE_KEY', 'DUPLICATE_FIELD')
                descriptor_keys.add(row['key'])
            _local_key(row['root_key'], path + '.root_key', checks)
            if row['artifact_key'] is not None:
                _local_key(row['artifact_key'], path + '.artifact_key', checks)
            checks.enum(row['state'], VIEW_STATES, path + '.state')
    if checks.shape(
        host,
        'origin evidence_basis grant_id view_key root_keys operation coherence checks policy limits',
        '$.capture.host',
        optional=('local_path_policy',),
    ):
        checks.enum(host['origin'], ORIGINS, '$.capture.host.origin')
        checks.enum(host['evidence_basis'], EVIDENCE_BASES, '$.capture.host.evidence_basis')
        checks.identifier(host['grant_id'], '$.capture.host.grant_id')
        if type(host.get('origin')) is str and type(host.get('grant_id')) is str:
            if host['grant_id'].startswith('syn:') != (host['origin'] == 'synthetic'):
                checks.fail('$.capture.host.grant_id', 'INVALID_FIELD_VALUE')
        _local_key(host['view_key'], '$.capture.host.view_key', checks)
        _request_local_ids(host['root_keys'], '$.capture.host.root_keys', checks, minimum=1)
        checks.enum(host['operation'], OPERATIONS, '$.capture.host.operation')
        checks.enum(host['coherence'], COHERENCE_STATES, '$.capture.host.coherence')
        if checks.shape(host['checks'], 'pre post final cleanup', '$.capture.host.checks'):
            for field in ('pre', 'post', 'final', 'cleanup'):
                checks.enum(host['checks'][field], CHECK_STATES, f'$.capture.host.checks.{field}')
        if checks.shape(host['policy'], 'allowed ready', '$.capture.host.policy'):
            checks.boolean(host['policy']['allowed'], '$.capture.host.policy.allowed')
            checks.boolean(host['policy']['ready'], '$.capture.host.policy.ready')
        if checks.shape(host['limits'], 'limit_hit', '$.capture.host.limits'):
            checks.boolean(host['limits']['limit_hit'], '$.capture.host.limits.limit_hit')
    artifacts = checks.sequence(capture.get('artifacts'), '$.capture.artifacts', 8)
    artifact_keys = set()
    for index, row in enumerate(artifacts):
        path = f'$.capture.artifacts[{index}]'
        if not checks.shape(row, 'key origin role target_key view_key source_identity source_version source_sha256 data limitations', path):
            continue
        if _local_key(row['key'], path + '.key', checks):
            if row['key'] in artifact_keys:
                checks.fail(path + '.key', 'DUPLICATE_KEY', 'DUPLICATE_FIELD')
            artifact_keys.add(row['key'])
        checks.enum(row['origin'], ORIGINS, path + '.origin')
        checks.enum(row['role'], ARTIFACT_ROLES, path + '.role', {'runtime', 'validation', 'policy'})
        _local_key(row['target_key'], path + '.target_key', checks)
        _local_key(row['view_key'], path + '.view_key', checks)
        checks.text(
            row['source_identity'], path + '.source_identity',
            allow_local_paths=allow_local_paths,
        )
        checks.text(row['source_version'], path + '.source_version')
        checks.digest(row['source_sha256'], path + '.source_sha256')
        if checks.text(
            row['data'], path + '.data', 24578, True,
            allow_local_paths=allow_local_paths,
        ):
            if len(row['data'].encode('utf-8')) > MAX_DATA_LENGTH:
                checks.fail(path + '.data', 'INVALID_ENCODING_OR_SIZE', 'INVALID_ENCODING_OR_SIZE')
        limitations = checks.sequence(row['limitations'], path + '.limitations', 5)
        if len(limitations) != len(set(limitations)) if all(type(item) is str for item in limitations) else False:
            checks.fail(path + '.limitations', 'DUPLICATE_FIELD', 'DUPLICATE_FIELD')
        for item in limitations:
            checks.enum(item, ARTIFACT_LIMITATIONS, path + '.limitations')
    components = checks.sequence(capture.get('components'), '$.capture.components', 8, 8)
    component_paths = []
    for index, row in enumerate(components):
        path = f'$.capture.components[{index}]'
        if checks.shape(row, 'path sha256', path):
            if row['path'] not in COMPONENTS:
                checks.fail(path + '.path', 'COMPONENT_PATH')
            checks.digest(row['sha256'], path + '.sha256')
            if type(row['path']) is str:
                component_paths.append(row['path'])
    if len(component_paths) != len(set(component_paths)):
        checks.fail('$.capture.components', 'COMPONENT_DUPLICATE', 'DUPLICATE_FIELD')
    if set(component_paths) != set(COMPONENTS):
        checks.fail('$.capture.components', 'COMPONENT_MISSING', 'MISSING_REQUIRED_FIELD')
    return checks.errors


def _compile_assessment(proposal, capture):
    """Compile one high-level request into the authoritative low-level packet."""
    request = {'proposal': proposal, 'capture': capture}
    errors = _request_check_input(request)
    if errors:
        return None, _invalid(errors)
    try:
        return _compile_assessment_validated(proposal, capture)
    except _InternalCompilerFailure:
        return None, _invalid([('INVALID_FIELD_VALUE', '$', 'INTERNAL_FAILURE')])
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        return None, _invalid([('INVALID_FIELD_VALUE', '$', 'INTERNAL_FAILURE')])


def _compile_assessment_validated(proposal, capture):
    prov = {'$': '$.proposal'}

    def remember(generated, supplied):
        prov.setdefault(generated, supplied)

    ptarget = proposal['target']
    ctarget = capture['target']
    target_id = 't:' + ptarget['key']
    captured_target_id = 't:' + ctarget['key']
    remember('$.target', '$.proposal.target')
    remember('$.host.target_binding', '$.capture.target')
    target = {
        'id': target_id,
        'harness': ptarget['harness'],
        'version': ptarget['version'],
        'surface': ptarget['surface'],
        'configuration_digest': ptarget['configuration_digest'],
    }
    target_binding = {
        'id': captured_target_id,
        'harness': ctarget['harness'],
        'version': ctarget['version'],
        'surface': ctarget['surface'],
        'configuration_digest': ctarget['configuration_digest'],
    }
    candidate = proposal['candidate']
    candidate_id = 'ca:' + candidate['key']
    need_ids = {need['key']: 'n:' + need['key'] for need in proposal['needs']}
    approach_ids = {approach['key']: 'p:' + approach['key'] for approach in proposal['approaches']}
    artifact_ids = {
        row['key']: ('syn:a:' if row['origin'] == 'synthetic' else 'a:') + row['key']
        for row in capture['artifacts']
    }
    artifact_rows = {row['key']: row for row in capture['artifacts']}
    def artifact_identifier(key):
        return artifact_ids.get(key, 'a:' + key)

    # Gather every span before assigning IDs.  Exact tuple deduplication is the
    # only deduplication performed; all raw lists have already been bounded.
    span_occurrences = {}
    requirement_occurrences = []

    def add_span(span, path):
        key = (span['artifact_key'], span['start_byte'], span['end_byte'])
        span_occurrences.setdefault(key, []).append(path)
        return key

    def add_narrative(narrative, path):
        for index, span in enumerate(narrative['citations']):
            add_span(span, f'{path}.citations[{index}]')

    for index, span in enumerate(candidate['citations']):
        add_span(span, f'$.proposal.candidate.citations[{index}]')
    for need_index, need in enumerate(proposal['needs']):
        for index, span in enumerate(need['citations']):
            add_span(span, f'$.proposal.needs[{need_index}].citations[{index}]')
        requirements = need['current_requirements'] or []
        for requirement_index, requirement in enumerate(requirements):
            requirement_occurrences.append((requirement, f'$.proposal.needs[{need_index}].current_requirements[{requirement_index}]'))
    for approach_index, approach in enumerate(proposal['approaches']):
        path = f'$.proposal.approaches[{approach_index}]'
        for field in ASSESSMENT_NARRATIVES:
            add_narrative(approach[field], path + '.' + field)
        add_narrative(approach['lift']['basis'], path + '.lift.basis')
        for coverage_index, coverage in enumerate(approach['coverage']):
            requirements = coverage['requirements'] or []
            for requirement_index, requirement in enumerate(requirements):
                requirement_occurrences.append((
                    requirement,
                    f'{path}.coverage[{coverage_index}].requirements[{requirement_index}]',
                ))

    def requirement_spans(requirement):
        if requirement['kind'] in ('source_present', 'source_equals'):
            return (requirement['span'],)
        return requirement['left'], requirement['right']

    for requirement, path in requirement_occurrences:
        for suffix, span in zip(
            ('span',) if requirement['kind'] != 'source_same' else ('left', 'right'),
            requirement_spans(requirement),
        ):
            add_span(span, path + '.' + suffix)

    sorted_spans = sorted(span_occurrences)
    if len(sorted_spans) > 64:
        return None, _invalid([('INVALID_ENCODING_OR_SIZE', '$.proposal', 'INVALID_ENCODING_OR_SIZE')])
    citation_ids = {key: f'ci:{index:02d}' for index, key in enumerate(sorted_spans)}
    citations = []
    for key in sorted_spans:
        artifact_key, start_byte, end_byte = key
        row = artifact_rows.get(artifact_key)
        if row is None:
            # The ID is intentionally reserved without inventing an artifact
            # hash or citation row.
            continue
        representation_sha256 = _sha256_text(row['data'])
        citations.append({
            'id': citation_ids[key],
            'artifact_id': artifact_identifier(artifact_key),
            'representation_sha256': representation_sha256,
            'start_byte': start_byte,
            'end_byte': end_byte,
        })
        remember(
            f'$.citations[{len(citations) - 1}]',
            min(span_occurrences[key]),
        )

    requirement_keys = []
    requirement_sources = {}
    for requirement, path in requirement_occurrences:
        spans = tuple(
            (span['artifact_key'], span['start_byte'], span['end_byte'])
            for span in requirement_spans(requirement)
        )
        if requirement['kind'] == 'source_equals':
            semantic = (requirement['kind'], spans, requirement['expected'])
        else:
            semantic = (requirement['kind'], spans)
        requirement_sources.setdefault(semantic, []).append(path)
        if semantic not in requirement_keys:
            requirement_keys.append(semantic)
    requirement_keys.sort()
    if len(requirement_keys) > 64:
        return None, _invalid([('INVALID_ENCODING_OR_SIZE', '$.proposal', 'INVALID_ENCODING_OR_SIZE')])
    relation_ids = {key: f're:{index:02d}' for index, key in enumerate(requirement_keys)}
    relations = []
    for semantic in requirement_keys:
        kind, spans = semantic[:2]
        identifiers = [citation_ids[span] for span in spans]
        relation = {'id': relation_ids[semantic], 'kind': kind}
        if kind == 'source_same':
            relation.update(left_citation_id=identifiers[0], right_citation_id=identifiers[1])
        else:
            relation['citation_id'] = identifiers[0]
            if kind == 'source_equals':
                relation['expected'] = semantic[2]
        relations.append(relation)
        remember(
            f'$.relations[{len(relations) - 1}]',
            min(requirement_sources[semantic]),
        )

    def low_narrative(narrative, path):
        result = {
            'text': narrative['text'],
            'citation_ids': [citation_ids[add_span(span, path + '.citations[%d]' % index)] for index, span in enumerate(narrative['citations'])],
        }
        remember(path.replace('$.proposal', '$.approaches'), path)
        return result

    low_candidate = {
        'id': candidate_id,
        'source_kind': candidate['source_kind'],
        'locator': candidate['locator'],
        'question': candidate['question'],
        'citation_ids': [
            citation_ids[(span['artifact_key'], span['start_byte'], span['end_byte'])]
            for span in candidate['citations']
        ],
    }

    low_needs = []
    for need_index, need in enumerate(proposal['needs']):
        current = []
        for requirement_index, requirement in enumerate(need['current_requirements'] or []):
            semantic = _requirement_semantic(requirement)
            if relation_ids[semantic] not in current:
                current.append(relation_ids[semantic])
            remember(
                f'$.needs[{need_index}].current_relation_ids[{len(current) - 1}]',
                f'$.proposal.needs[{need_index}].current_requirements[{requirement_index}]',
            )
        low_needs.append({
            'id': need_ids[need['key']],
            'statement': need['statement'],
            'citation_ids': [
                citation_ids[(span['artifact_key'], span['start_byte'], span['end_byte'])]
                for span in need['citations']
            ],
            'load_bearing': need['load_bearing'],
            'current_relation_ids': current,
        })
    low_approaches = []
    for approach_index, approach in enumerate(proposal['approaches']):
        path = f'$.proposal.approaches[{approach_index}]'
        by_need = {row['need_key']: row for row in approach['coverage']}
        assignments = []
        for need_index, need in enumerate(proposal['needs']):
            coverage = by_need.get(need['key'])
            assignment_path = (
                f'{path}.coverage[{next((i for i, row in enumerate(approach["coverage"]) if row["need_key"] == need["key"]), 0)}]'
                if coverage is not None else path + '.coverage'
            )
            if coverage is None:
                unresolved = MISSING_REQUIREMENT_MARKER
                requirement_values = []
            else:
                unresolved = coverage['unresolved']
                requirement_values = coverage['requirements'] or []
            ids = []
            for requirement in requirement_values:
                semantic = _requirement_semantic(requirement)
                if relation_ids[semantic] not in ids:
                    ids.append(relation_ids[semantic])
            assignments.append({
                'need_id': need_ids[need['key']],
                'relation_ids': ids,
                'unresolved': unresolved,
            })
            remember(
                f'$.approaches[{approach_index}].need_relations[{len(assignments) - 1}]',
                assignment_path,
            )
        low_approaches.append({
            'id': approach_ids[approach['key']],
            'need_relations': assignments,
            'lift': {
                'amount': approach['lift']['amount'],
                'unit': approach['lift']['unit'],
                'basis': low_narrative(approach['lift']['basis'], path + '.lift.basis'),
            },
            **{
                field: low_narrative(approach[field], path + '.' + field)
                for field in ASSESSMENT_NARRATIVES
            },
        })
    low_artifacts = []
    for index, row in enumerate(capture['artifacts']):
        low_artifacts.append({
            'id': artifact_ids[row['key']],
            'origin': row['origin'],
            'role': row['role'],
            'target_id': 't:' + row['target_key'],
            'view_id': 'v:' + row['view_key'],
            'source_identity': row['source_identity'],
            'source_version': row['source_version'],
            'source_sha256': row['source_sha256'],
            'representation_sha256': _sha256_text(row['data']),
            'data': row['data'],
            'limitations': list(row['limitations']),
        })
        remember(f'$.artifacts[{index}]', f'$.capture.artifacts[{index}]')
    view = capture['view']
    view_id = 'v:' + view['key']
    low_view = {
        'id': view_id,
        'target_id': 't:' + view['target_key'],
        'root_ids': ['r:' + key for key in view['root_keys']],
        'operation': view['operation'],
        'descriptors': [],
    }
    for index, row in enumerate(view['descriptors']):
        low_view['descriptors'].append({
            'id': 'd:' + row['key'],
            'root_id': 'r:' + row['root_key'],
            'artifact_id': None if row['artifact_key'] is None else artifact_identifier(row['artifact_key']),
            'state': row['state'],
        })
        remember(f'$.view.descriptors[{index}]', f'$.capture.view.descriptors[{index}]')
    host = capture['host']
    low_host = {
        'origin': host['origin'],
        'evidence_basis': host['evidence_basis'],
        'grant_id': host['grant_id'],
        'target_binding': target_binding,
        'view_id': 'v:' + host['view_key'],
        'root_ids': ['r:' + key for key in host['root_keys']],
        'operation': host['operation'],
        'coherence': host['coherence'],
        'checks': copy.deepcopy(host['checks']),
        'policy': copy.deepcopy(host['policy']),
        'limits': {
            'decoded_bytes': sum(len(row['data'].encode('utf-8')) for row in capture['artifacts']),
            'artifact_count': len(capture['artifacts']),
            'limit_hit': host['limits']['limit_hit'],
        },
    }
    if 'local_path_policy' in host:
        low_host['local_path_policy'] = host['local_path_policy']
    low_components = copy.deepcopy(capture['components'])
    invocation = {
        'contract': CONTRACT,
        'candidate': low_candidate,
        'target': target,
        'view': low_view,
        'host': low_host,
        'artifacts': low_artifacts,
        'citations': citations,
        'relations': relations,
        'needs': low_needs,
        'approaches': low_approaches,
        'components': low_components,
    }
    # Keep a path for every generated container and let the authoritative
    # low-level checker map any future cross-record diagnostic through it.
    for generated, supplied in (
        ('$.candidate', '$.proposal.candidate'),
        ('$.view', '$.capture.view'),
        ('$.host', '$.capture.host'),
        ('$.artifacts', '$.capture.artifacts'),
        ('$.citations', '$.proposal'),
        ('$.relations', '$.proposal'),
        ('$.needs', '$.proposal.needs'),
        ('$.approaches', '$.proposal.approaches'),
        ('$.components', '$.capture.components'),
    ):
        remember(generated, supplied)
    admitted, invalid = _admit_assessment(invocation, diagnostic_paths=prov)
    return admitted, invalid


def _requirement_semantic(requirement):
    if requirement['kind'] in ('source_present', 'source_equals'):
        spans = ((requirement['span']['artifact_key'], requirement['span']['start_byte'], requirement['span']['end_byte']),)
    else:
        spans = (
            (requirement['left']['artifact_key'], requirement['left']['start_byte'], requirement['left']['end_byte']),
            (requirement['right']['artifact_key'], requirement['right']['start_byte'], requirement['right']['end_byte']),
        )
    return (
        (requirement['kind'], spans, requirement['expected'])
        if requirement['kind'] == 'source_equals'
        else (requirement['kind'], spans)
    )


def _sha256_text(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()
