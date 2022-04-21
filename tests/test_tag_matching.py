from fileconnector import TagMatcher

import pytest


@pytest.mark.parametrize("key", ["key", "KEY", "kEy"])
def test_get_tag(key):
    existing_key = "key"
    existing_tags = {existing_key: True}
    matcher = TagMatcher(existing_tags)

    assert existing_key == matcher.get_tag(key)


def test_get_tag_throws_value_error_on_missing_tag():
    existing_tags = {"key": True}
    matcher = TagMatcher(existing_tags)

    with pytest.raises(ValueError):
        matcher.get_tag("missing")


def test_getting_possible_values():
    existing_tags = {"Distri": ["Ubuntu", "CentOS"]}
    matcher = TagMatcher(existing_tags)

    assert matcher.is_possible_value("distri", "Ubuntu") is True


def test_getting_possible_values_returns_false_if_missing():
    existing_tags = {"Distri": ["Ubuntu", "CentOS"]}
    matcher = TagMatcher(existing_tags)

    assert matcher.is_possible_value("distri", "RHEL", raise_error=False) is False


def test_getting_possible_values_can_raise_exc_if_failing():
    existing_tags = {"Distri": ["Ubuntu", "CentOS"]}
    matcher = TagMatcher(existing_tags)

    with pytest.raises(ValueError):
        assert matcher.is_possible_value("distri", "RHEL", raise_error=True)
