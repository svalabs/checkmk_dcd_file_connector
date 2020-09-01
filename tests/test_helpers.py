import pytest
import csvconnector


@pytest.fixture
def hostname_field():
    return 'hostname'


def test_getting_host_label(hostname_field):
    host = {
        hostname_field: 'testhost',
        'label_LaBeL1': 1,
        'label_another_key': 'AS df Gh',
    }

    expected_label = {
        'label1': 1,
        'another_key': 'AS df Gh',
    }

    assert expected_label == csvconnector.get_host_label(host, hostname_field)


@pytest.mark.parametrize("key, expected_key, value", (
    ('label_LaBeL1', 'label1', 1),  # key should be lowercased
    ('label_label2', 'label2', 2),
    ('label_Dont_Lowercase_Value', 'dont_lowercase_value', 'DevOps'),
    ('label_dont_lowercase_value2', 'dont_lowercase_value2', 'ITIL'),
))
def test_getting_host_label_transformation(hostname_field, key, expected_key, value):
    host = {hostname_field: 'testhost', key: value}

    expected_label = {expected_key: value}

    assert expected_label == csvconnector.get_host_label(host, hostname_field)


@pytest.mark.parametrize("attributes, expected_result",[
    ({}, {}),
    ({'tag_foo': 'bar'}, {}),
    ({'tag_foo': 'bar', 'city': 'Mexico'}, {'city': 'Mexico'}),
    ({'song': 'surfacing', 'city': 'Mexico'},
     {'song': 'surfacing', 'city': 'Mexico'}),
])
def test_getting_host_label_ignores_tags(attributes, expected_result):
    host = {hostname_field: 'testhost'}
    host.update(attributes)

    assert expected_result == csvconnector.get_host_label(host, hostname_field)

@pytest.mark.parametrize("hostname, expected_hostname", [
    ('ABcd', 'abcd'),
    ('aBCd', 'abcd'),
    ('my host', 'my_host'),
])
def test_normalize_hostname(hostname, expected_hostname):
    assert expected_hostname == csvconnector.normalize_hostname(hostname)


@pytest.mark.parametrize("value", [
    'tAg_abcd',
    'tag_defg',
    'TAG_GHIJ',
    pytest.param('tagged_value', marks=pytest.mark.xfail),
    pytest.param('something_tag_thingy', marks=pytest.mark.xfail),
])
def test_is_tag(value):
    assert csvconnector.is_tag(value)


@pytest.mark.parametrize("host, expected_tags", [
    ({"name": "test1", "label_foo": "bar", "tag_cloud": "AWS"}, {"tag_cloud": "AWS"}),
])
def test_getting_host_tags(host, expected_tags):
    assert csvconnector.get_host_tags(host) == expected_tags


@pytest.mark.parametrize("tags_from_api, expected_tags", [
    ({}, {}),
    ([{"id": "agent", "tags": [{"aux_tags": ["tcp"],"id": "cmk-agent","title": "Normal Checkmk agent, or special agent if configured"},{"aux_tags": ["tcp"],"id": "all-agents","title": "Normal Checkmk agent, all configured special agents"},{"aux_tags": ["tcp"],"id": "special-agents","title": "No Checkmk agent, all configured special agents"},{"aux_tags": [],"id": "no-agent","title": "No agent"}],"title": "Check_MK Agent","topic": "Data sources"},{"id": "piggyback","tags": [{"aux_tags": [],"id": "auto-piggyback","title": "Use piggyback data from other hosts if present"},{"aux_tags": [],"id": "piggyback","title": "Always use and expect piggyback data"},{"aux_tags": [],"id": "no-piggyback","title": "Never use piggyback data"}],"title": "Piggyback","topic": "Data sources"},{"id": "snmp_ds","tags": [{"aux_tags": [],"id": "no-snmp","title": "No SNMP"},{"aux_tags": ["snmp"],"id": "snmp-v2","title": "SNMP v2 or v3"},{"aux_tags": ["snmp"],"id": "snmp-v1","title": "SNMP v1"}],"title": "SNMP","topic": "Data sources"},{"id": "address_family","tags": [{"aux_tags": ["ip-v4"],"id": "ip-v4-only","title": "IPv4 only"},{"aux_tags": ["ip-v6"],"id": "ip-v6-only","title": "IPv6 only"},{"aux_tags": ["ip-v4","ip-v6"],"id": "ip-v4v6","title": "IPv4/IPv6 dual-stack"},{"aux_tags": [],"id": "no-ip","title": "No IP"}],"title": "IP Address Family","topic": "Address"}],
    {"tag_agent": ["cmk-agent", "all-agents", "special-agents","no-agent",],"tag_piggyback": ["auto-piggyback","piggyback","no-piggyback",],"tag_snmp_ds": ["no-snmp","snmp-v2","snmp-v1",],"tag_address_family": ["ip-v4-only","ip-v6-only","ip-v4v6","no-ip"]})
])
def test_create_hostlike_tags(tags_from_api, expected_tags):
    assert expected_tags == csvconnector.create_hostlike_tags(tags_from_api)
