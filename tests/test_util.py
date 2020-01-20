import tempfile

import pytest

from autossl import util
from autossl.server.local import LocalServer


@pytest.mark.parametrize('class_path, exception_type', [
    ('MyClass', ValueError),
    ('my.package.does.not.exist.MyClass', ImportError),
    ('autossl.server.local.Dummy', AttributeError),
])
def test_str_to_class_error(class_path, exception_type):
    with pytest.raises(exception_type):
        util.str_to_class(class_path=class_path)


@pytest.mark.parametrize('class_path,class_type', [
    ('autossl.server.local.LocalServer', LocalServer),
])
def test_str_to_class(class_path, class_type):
    assert util.str_to_class(class_path=class_path) == class_type


@pytest.mark.parametrize('path', [
    None,
    util.Path(tempfile.mkdtemp())
])
def test_TempDir(path):
    with util.TempDir(path=path) as temp_folder:
        assert temp_folder.path.exists()
    assert not temp_folder.path.exists()
