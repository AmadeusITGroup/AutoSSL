"""
Tests for Local file logging tracking implementation
"""
import os
import pytest

from autossl import exception, ssl, util
from autossl.tracking import local, base

from tests import util as tests_util


@pytest.fixture(scope="module")
def local_logging_tracking():
    ssl_blueprint_name = 'tst.ov.example.com.yaml'
    ssl_blueprint_path = tests_util.DATA_PATH / ssl_blueprint_name

    with util.TempDir() as temp_folder:
        yield local.LocalFileTracking(
            ssl_blueprint_path=ssl_blueprint_path,
            log_folder=str(temp_folder.path),
        )


def test_create_basic(local_logging_tracking):
    # log file does not exist before create
    assert not os.path.exists(local_logging_tracking.log_file_path)
    local_logging_tracking.create(tracking_type=base.TrackingType.Renewal)
    # and is well created after call to create
    assert os.path.isfile(local_logging_tracking.log_file_path)

    assert local_logging_tracking.retrieve_data(name='log').startswith(
        b"Creation of the following certificate requested")


def test_save_data(local_logging_tracking):
    local_logging_tracking.save_data(name='data name', data_type=None, local_path=None, content=b'my data content')


def test_update(local_logging_tracking):
    local_logging_tracking.update(message='insert message')
    assert local_logging_tracking.retrieve_data(name='log') == b'insert message'


def test_refresh(local_logging_tracking):
    local_logging_tracking.refresh(record_id=None)


def test_retrieve_data(local_logging_tracking):
    with pytest.raises(ValueError):
        local_logging_tracking.retrieve_data()

    with pytest.raises(exception.NotFound):
        local_logging_tracking.retrieve_data(name='data_identifier')

    with pytest.raises(exception.NotFound):
        local_logging_tracking.retrieve_data(data_type=ssl.DataType.Certificate)

    local_logging_tracking.save_data(name='data_identifier', data_type=ssl.DataType.Certificate,
                                     content=b'my data content')
    assert local_logging_tracking.retrieve_data(name='data_identifier') == b'my data content'
    assert local_logging_tracking.retrieve_data(data_type=ssl.DataType.Certificate) == b'my data content'


def test_close_for_failure(local_logging_tracking):
    local_logging_tracking.close_for_failure(message='Operation failed !')
    assert local_logging_tracking.retrieve_data(name='log') == b'Operation failed !'


def test_close_for_success(local_logging_tracking):
    local_logging_tracking.close_for_success(message='Operation completed successfully.')
    assert local_logging_tracking.retrieve_data(name='log') == b'Operation completed successfully.'
