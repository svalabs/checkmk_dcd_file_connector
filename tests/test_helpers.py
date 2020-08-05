import pytest
import csvconnector.helper as helper


def test_getting_host_label():
    hostname_field = 'hostname'

    host = {
        hostname_field: 'testhost',
        'LaBeL1': 1,
        'label2': 2,
        'Dont_Lowercase_Value': 'DevOps',
        'dont_lowercase_value2': 'ITIL',
    }

    expected_label = {
        'label1': 1,  # key should be lowercased
        'label2': 2,
        'dont_lowercase_value': 'DevOps',
        'dont_lowercase_value2': 'ITIL',
    }

    assert expected_label == helper.get_host_label(host, hostname_field)


@pytest.mark.parametrize("hostname, expected_hostname", [
    ('ABcd', 'abcd'),
    ('aBCd', 'abcd'),
    ('my host', 'my_host'),
])
def test_normalize_hostname(hostname, expected_hostname):
    assert expected_hostname == helper.normalize_hostname(hostname)
