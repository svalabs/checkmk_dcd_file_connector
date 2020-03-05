import csvconnector.helper as helper


def test_getting_host_label():
    hostname_field = 'hostname'

    host = {
        hostname_field: 'testhost',
        'label1': 1,
        'label2': 2,
    }

    expected_label = {
        'label1': 1,
        'label2': 2,
    }

    assert expected_label == helper.get_host_label(host, hostname_field)
