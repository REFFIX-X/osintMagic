from osintmagic.utils.permutations import (
    dork_queries,
    email_candidates,
    expand_variants,
    name_candidates,
)


def test_expand_variants():
    assert expand_variants("alice") == ["alice"]
    assert expand_variants("a{?}b") == ["ab", "a_b", "a-b", "a.b"]


def test_name_candidates():
    cands = name_candidates("Jane", "Doe")
    assert "janedoe" in cands
    assert "jane.doe" in cands
    assert "j.doe" in cands
    assert "janed" in cands
    # no duplicates
    assert len(cands) == len(set(cands))


def test_name_candidates_with_middle():
    cands = name_candidates("Jane", "Doe", "Mary")
    assert "janemarydoe" in cands


def test_email_candidates():
    emails = email_candidates("Jane", "Doe")
    assert "jane.doe@gmail.com" in emails
    assert "jane.doe@outlook.com" in emails
    assert "jdoe@gmail.com" in emails


def test_dork_queries():
    dorks = dork_queries("Jane Doe")
    assert any("Jane Doe" in d for d in dorks)
    assert any("linkedin.com/in" in d for d in dorks)
