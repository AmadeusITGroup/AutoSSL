import importlib
import logging
try:
    # Python 3
    from pathlib import Path  # noqa: F401
except ImportError:
    #  Python 2
    from pathlib2 import Path  # noqa: F401
import requests
import shutil
from six import PY2  # noqa: F401
import tempfile

from . import exception

logger = logging.getLogger(__name__)


def check_http_response_ok(response):
    """Validate http response code

    all codes not in 2xx will raise an exception

    :param response: requests Http response
    :type response: requests.Response
    :return: same http response
    :rtype: requests.Response
    :raise exception.HttpCodeException: if http status code in not in 2xx
    """
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as ex:
        raise exception.HttpCodeException(ex)
    return response


def str_to_class(class_path):
    """Dynamically import and return class type from full module and class path

    :param class_path:
    :type class_path: str
    :return: Type of the class to instantiate
    :rtype: type
    :raise ImportError: if module does not exist
    :raise AttributeError: if class not found in specified module
    """
    module_name, class_name = class_path.rsplit('.', 1)
    try:
        module_ = importlib.import_module(module_name)
        try:
            return getattr(module_, class_name)
        except AttributeError:
            logging.exception('Class %s not found in module %s.' % (class_name, module_name))
            raise
    except ImportError:
        logging.exception('Module %s does not exist.' % module_name)
        raise


class TempDir(object):
    def __init__(self, path=None):
        """Create Temporary directory that can be used with context manager for automated deletion at __exit__
        :param path: local path. If None, temporary folder will be created at `__enter__` thanks to `tempfile.mkdtemp()`
        :type path: str or pathlib.Path
        """
        self.input_path = path
        self.path = None

    def __enter__(self):
        self.path = Path(str(self.input_path) if self.input_path else tempfile.mkdtemp())
        if not self.path.is_dir():
            raise IOError("Specified path {} is not a directory.".format(self.path))
        return self

    def __exit__(self, *args):
        if self.path.exists() and self.path.is_dir():
            shutil.rmtree(str(self.path), ignore_errors=True)
