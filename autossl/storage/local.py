import logging
import os
import shutil

from .. import exception, util
from . import base

logger = logging.getLogger(__name__)


class LocalFileStorage(base.Storage):

    def __init__(self, path, tracking_record_id=None, **kwargs):
        super(LocalFileStorage, self).__init__(tracking_record_id=tracking_record_id, **kwargs)
        self.path = util.Path(os.path.expandvars(path))
        if not self.path.is_dir():
            raise IOError("Invalid folder path specified: '%s'" % self.path)

    def save_data(self, name, content=None, local_path=None, **kwargs):
        output_file_path = self.path / name

        if content is not None:
            if local_path:
                logger.warning("local_path path '{}' ignored as content also specified.".format(local_path))
            output_file_path.write_bytes(content)
        else:
            shutil.copy(str(local_path), str(output_file_path))

    def retrieve_data(self, name, **kwargs):
        file_path = self.path / name
        if not file_path.exists():
            raise exception.NotFound("Path %s does not exists." % file_path)
        return file_path.read_bytes()
