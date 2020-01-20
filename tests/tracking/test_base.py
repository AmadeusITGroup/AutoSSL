"""
Tests for Base tracking implementation should not raise any error even without parent implementation
"""
import pytest

from autossl.tracking import base

from tests import util as tests_util


@pytest.fixture(scope="module")
def base_tracking():
    ssl_blueprint_name = 'tst.ov.example.com.yaml'
    ssl_blueprint_path = tests_util.DATA_PATH / ssl_blueprint_name

    base_tracking_instance = base.Tracking(ssl_blueprint_path)

    # basic checks
    assert base_tracking_instance.ssl_blueprint_path is not None

    yield base_tracking_instance


def test_create_basic(base_tracking):
    base_tracking.create(tracking_type=base.TrackingType.Renewal)


def test_save_data(base_tracking):
    base_tracking.save_data(name=None, data_type=None, local_path=None,
                            content=None, extra_param1='value1', extra_param2='value2')


def test_update(base_tracking):
    base_tracking.update(message=None)


def test_refresh(base_tracking):
    base_tracking.refresh(record_id=None)


def test_retrieve_data(base_tracking):
    base_tracking.retrieve_data(name=None, data_type=None, extra_param1='value1', extra_param2='value2')


def test_close_for_failure(base_tracking):
    base_tracking.close_for_failure(message=None)


def test_close_for_success(base_tracking):
    base_tracking.close_for_success(message=None)
