"""
Tests for Git storage implementation
"""
import pytest
import tempfile

import git

from autossl import exception
from autossl.storage import gitscm

from tests import util as tests_util


@pytest.fixture(scope="function")
def folder_name():
    return None


@pytest.fixture(scope="function")
def tracking_record_id():
    return None


@pytest.fixture(scope="function")
def git_storage(tmp_path, folder_name, tracking_record_id):
    # initialize bare git repository in temporary folder
    git.Repo.init(str(tmp_path), bare=True)

    # return git storage instance
    yield gitscm.GitStorage(git_url=str(tmp_path), folder=folder_name, tracking_record_id=tracking_record_id,
                            config_user_name='Test User', config_user_email='test.user@autossl.com')


def test_retrieve_data_error(git_storage):
    with pytest.raises(exception.NotFound):
        git_storage.retrieve_data(name='my_file_name')


@pytest.mark.parametrize('folder_name,tracking_record_id', [
    (None, None),
    ('first_folder', 123456789)
])
def test_save_retrieve_data_from_content(git_storage, folder_name, tracking_record_id):
    file_name = tests_util.get_random_ascii_string()
    file_content = tests_util.get_random_text()
    # save content in main repo
    git_storage.save_data(name=file_name, content=file_content)

    assert git_storage.retrieve_data(name=file_name) == file_content


@pytest.mark.parametrize('folder_name', [
    None,
    'other_folder'
])
def test_save_retrieve_data_from_local_path(git_storage, folder_name):
    file_name = tests_util.get_random_ascii_string()
    file_content = tests_util.get_random_text()

    # save content in main repo from local_path
    with tempfile.NamedTemporaryFile() as local_file:
        local_file.write(file_content)
        local_file.seek(0)
        git_storage.save_data(name=file_name, local_path=local_file.name)

    assert git_storage.retrieve_data(name=file_name) == file_content


def test_save_retrieve_data_same_file_twice(git_storage):
    file_name = tests_util.get_random_ascii_string()
    file_content = tests_util.get_random_text()

    # save content in main repo
    git_storage.save_data(name=file_name, content=file_content)

    assert git_storage.retrieve_data(name=file_name) == file_content

    # try to save same data a 2nd time should not fail
    git_storage.save_data(name=file_name, content=file_content)

    assert git_storage.retrieve_data(name=file_name) == file_content


def test_git_url_with_username_password_present():
    git_url = 'https://test/heya.git'
    username = 'Jack'
    password = 'thisisaclearpassword,stopreading'
    new_git_url = gitscm.git_url_with_username_password(git_url, username, password)
    assert new_git_url == git_url.replace('://', '://{}:{}@'.format(username, password))


def test_git_url_with_username_password_absent():
    git_url = 'https://test/heya.git'
    new_git_url = gitscm.git_url_with_username_password(git_url, None, None)
    assert git_url == new_git_url
