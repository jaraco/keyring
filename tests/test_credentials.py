from keyring.credentials import EnvironCredential


def test_equal_credentials_compare_equal():
    assert EnvironCredential("USER", "PASSWORD") == EnvironCredential("USER", "PASSWORD")


def test_different_credentials_compare_unequal():
    assert EnvironCredential("USER", "PASSWORD") != EnvironCredential("USER", "OTHER")


def test_comparison_with_non_credentials_returns_false():
    credential = EnvironCredential("USER", "PASSWORD")
    for other in (None, 42, object(), "USER", ["USER"]):
        assert credential != other
