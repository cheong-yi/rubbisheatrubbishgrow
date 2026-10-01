"""Complete, inert display of a validated non-authorizing foundation packet."""
from . import raw_intake


def render_assessment_markdown(result, /):
    encoded = raw_intake.canonical_result_bytes(result).decode('utf-8')
    replacements = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '@': '&#64;', '`': '&#96;', '|': '&#124;'}
    escaped = ''.join(replacements.get(character, character) for character in encoded)
    return '# RERG non-authorizing packet\n\n<pre>' + escaped + '</pre>\n'
