import pytest
import csvconnector


@pytest.fixture
def hostname_field():
    return 'hostname'


def test_getting_host_label(hostname_field):
    host = {
        hostname_field: 'testhost',
        'LaBeL1': 1,
        'another_key': 'AS df Gh',
    }

    expected_label = {
        'label1': 1,
        'another_key': 'AS df Gh',
    }

    assert expected_label == csvconnector.get_host_label(host, hostname_field)


@pytest.mark.parametrize("key, expected_key, value", (
    ('LaBeL1', 'label1', 1),  # key should be lowercased
    ('label2', 'label2', 2),
    ('Dont_Lowercase_Value', 'dont_lowercase_value', 'DevOps'),
    ('dont_lowercase_value2', 'dont_lowercase_value2', 'ITIL'),
))
def test_getting_host_label_transformation(hostname_field, key, expected_key, value):
    host = {hostname_field: 'testhost', key: value}

    expected_label = {expected_key: value}

    assert expected_label == csvconnector.get_host_label(host, hostname_field)


@pytest.mark.parametrize("hostname, expected_hostname", [
    ('ABcd', 'abcd'),
    ('aBCd', 'abcd'),
    ('my host', 'my_host'),
])
def test_normalize_hostname(hostname, expected_hostname):
    assert expected_hostname == csvconnector.normalize_hostname(hostname)
