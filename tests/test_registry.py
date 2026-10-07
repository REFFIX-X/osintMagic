from osintmagic import get_sources


def test_all_categories_registered():
    for category in ("username", "email", "domain", "ip", "person"):
        assert get_sources(category), f"no sources registered for {category}"


def test_username_source_count():
    assert len(get_sources("username")) >= 40


def test_category_filtering_returns_category_sources():
    usernames = {s.name for s in get_sources("username")}
    domains = {s.name for s in get_sources("domain")}
    assert "GitHub" in usernames
    assert "DNS Records" in domains
    # no pure-username site leaks into the domain category
    assert not {"GitHub", "Reddit", "Twitch"}.intersection(domains)
    # paste/leak sources are on-demand, so they are excluded from automatic scans
    assert "Paste / Code Leaks" not in usernames
    assert "Leak / paste mentions" not in domains


def test_sources_have_required_attrs():
    for source in get_sources():
        assert source.name
        assert source.category


def test_sources_are_instances_not_classes():
    # Regression guard: a class registered with `register(SomeClass)` would make
    # `check(target)` an unbound-method call and crash the deep scans.
    for source in get_sources():
        assert not isinstance(source, type), f"{source!r} was registered as a class, not an instance"
