import pytest

from custom_components.filter_compiler import FilterCompiler
from custom_components.filter_compiler.term_builder import FilterError, build_term
def test_unknown_field_is_rejected():
    with pytest.raises(FilterError):
        build_term("system.secret", "==", "x")
