"""
Tests for base storage implementation, to ensure it must always be overridden
"""
import pytest

from autossl.storage import base


@pytest.fixture(scope="function")
def base_storage():
    yield base.Storage(tracking_record_id=None)


def test_save_data(base_storage):
    with pytest.raises(NotImplementedError):
        base_storage.save_data(name='my_data_name', data_type=None, content=None, local_path=None)


def test_retrieve_data(base_storage):
    with pytest.raises(NotImplementedError):
        base_storage.retrieve_data(name='my_file_name', data_type=None)
