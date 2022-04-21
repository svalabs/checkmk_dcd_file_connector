import pytest
import fileconnector


def test_chunking(chunk_size=3):
    for chunk in fileconnector.chunks(range(10), chunk_size):
        assert len(chunk) == chunk_size


def test_chunking_fills_with_none():
    chunk_size = 3
    original_iter = list(range(10))
    assert len(original_iter) % 3 != 0

    for index, chunk in enumerate(fileconnector.chunks(original_iter, chunk_size)):
        print(chunk)
        if index != chunk_size:
            assert len([x for x in chunk if x is not None]) == chunk_size
            continue  # No further checks

        chunk_length = len(chunk)
        empty_elements = [x for x in chunk if x is None]
        assert empty_elements

        filled_elements = [x for x in chunk if x is not None]
        assert chunk_size == len(filled_elements + empty_elements)
