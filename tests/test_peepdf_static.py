import pytest

from peepdf.peepdf import check_for_function

@pytest.mark.parametrize(("data", "result"), [
    ("evalua", False),
    ("eval()", True),
    ("eval (", True),
    ("(eval)", False),
])
def test_check_for_function_eval(data, result):
    assert check_for_function("eval", data) == result
