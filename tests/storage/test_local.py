"""
Tests for local storage implementation
"""
import os
import pytest

from autossl import exception
from autossl.storage import local

from tests import util as tests_util


@pytest.fixture(scope="function")
def local_storage(tmp_path):
    yield local.LocalFileStorage(path=str(tmp_path))


def test_init_error():
    with pytest.raises(IOError):
        local.LocalFileStorage(path=os.path.join(os.getcwd(), 'my', 'missing', 'path'))


def test_retrieve_data_error(local_storage):
    with pytest.raises(exception.NotFound):
        local_storage.retrieve_data(name='my_file_name')


def test_save_retrieve_data_from_content(local_storage):
    file_name = tests_util.get_random_ascii_string()
    file_content = tests_util.get_random_text()

    # save data in main repo from content
    local_storage.save_data(name=file_name,
                            content=file_content,
                            # local_path here will be ignored as content is already provided
                            local_path='not_existing_path')
    assert local_storage.retrieve_data(name=file_name) == file_content


def test_save_retrieve_data_from_local_file(tmp_path, local_storage):
    file_name = tests_util.get_random_ascii_string()
    file_content = tests_util.get_random_text()

    # save data with content from local file
    # first create a temporary file on disk that will be used as source of the data
    source_file_path = tmp_path / file_name
    source_file_path.write_bytes(file_content)

    # save data
    file_name2 = tests_util.get_random_ascii_string()
    local_storage.save_data(name=file_name2, local_path=source_file_path)

    assert local_storage.retrieve_data(name=file_name2) == file_content

    local_storage.save_data(name=file_name2, local_path=source_file_path)
    assert local_storage.retrieve_data(name=file_name2) == file_content
