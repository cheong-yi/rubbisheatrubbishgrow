"""Optional bounded Hypothesis property for RERG's percent decoder."""

from urllib.parse import unquote

from hypothesis import given, settings
from hypothesis import strategies as st

from rerg import raw_derivation


@settings(max_examples=100, deadline=None)
@given(st.text(max_size=256))
def test_percent_decoder_matches_unquote_for_bounded_text(value: str) -> None:
    assert raw_derivation._percent_decode(value) == unquote(value)
