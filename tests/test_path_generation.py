from fileconnector import generate_path_from_labels, FOLDER_PLACEHOLDER

import pytest


@pytest.mark.parametrize(
    "labels, keys, expected_path",
    [
        (
            {"stadt": "berlin", "land": "deutschland", "fluss": "spree"},
            ["stadt", "land", "fluss"],
            ["berlin", "deutschland", "spree"],
        ),
        (
            {"stadt": "berlin", "land": "deutschland", "fluss": "spree"},
            ["land", "fluss"],
            ["deutschland", "spree"],
        ),
        (
            {"stadt": "berlin", "land": "deutschland", "fluss": "spree"},
            ["nonexisting"],
            [FOLDER_PLACEHOLDER],
        ),
        (
            {"stadt": "berlin", "land": "deutschland", "fluss": "spree"},
            ["stadt", "strasse", "fluss"],
            ["berlin", FOLDER_PLACEHOLDER, "spree"],
        ),
    ],
)
def test_path_generation(labels, keys, expected_path):
    assert expected_path == generate_path_from_labels(labels, keys)


@pytest.mark.parametrize("length", [1, 2])
def test_no_labels(length):
    assert [FOLDER_PLACEHOLDER] * length == generate_path_from_labels({}, [], length)


def test_no_labels_no_length():
    assert [] == generate_path_from_labels({}, [])
