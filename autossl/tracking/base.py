from enum import Enum
import logging

logger = logging.getLogger(__name__)


class TrackingType(Enum):
    """list of tracking types supported."""
    # End-to-end flow of certificate renewal and deployment on servers
    Renewal = 'renewal'
    # Simply deploy existing valid certificate on new or outdated servers
    Synchronize = 'synchronize'


class Tracking(object):

    def __init__(self, ssl_blueprint_path, **kwargs):
        r"""Api to tracking server for specified input ssl blueprint

        :param ssl_blueprint_path: local path to ssl blueprint
        :type ssl_blueprint_path: pathlib.Path
        :param \**kwargs: generic key/value parameters
        :type \**kwargs: dict
        """
        self.ssl_blueprint_path = ssl_blueprint_path

    def create(self, tracking_type, servers=None):
        """Create a tracking record with details of current SSL blueprint

        :param tracking_type: Type of tracking. Can be used to customized tracking record content.
        :type tracking_type: TrackingType
        :param servers: List of servers in scope of the action. All servers from config if None specified here.
        :type servers: list
        :return: Identifier for the created record
        :rtype: str
        """
        logger.debug("Nothing to do for 'create' tracking default implementation.")

    def save_data(self, name, data_type, local_path=None, content=None, **kwargs):
        r"""Save input data in tracking system

        :param name: name of the file to attach to the tracking record
        :type name: str
        :param data_type: type of data to save
        :type data_type: ssl.DataType
        :param local_path: local path to file to attach to the tracking record
        :type local_path: pathlib.Path
        :param content: content of the file to attach to the tracking record
        :type content: bytes
        :param \**kwargs: generic key/value parameters
        :type kwargs: dict
        """
        logger.debug("Nothing to do for 'save_data' tracking default implementation.")

    def update(self, message):
        """Update tracking record

        :param message: text to add to tracking record
        :type message: str
        """
        logger.debug("Nothing to do for 'update' tracking default implementation.")

    def refresh(self, record_id):
        """Update current tracking instance with last changes from tracking record on server side

        :param record_id: identifier of the record to refresh
        """
        logger.debug("Nothing to do for 'refresh' tracking default implementation.")

    def retrieve_data(self, name=None, data_type=None, **kwargs):
        r"""Retrieve specified data from tracking system

        :param name: Name of file/data to retrieve
        :type name: str
        :param data_type: type of data to retrieve
        :type data_type: ssl.DataType
        :param \**kwargs: generic key/value parameters
        :type kwargs: dict
        :return: file content
        :rtype: bytes
        """
        logger.debug("Nothing to do for 'retrieve_data' tracking default implementation.")

    def close_for_failure(self, message):
        """Specify action is completed with a failed status

        :param message: custom message
        :type message: str
        """
        logger.debug("Nothing to do for 'close_for_failure' tracking default implementation.")

    def close_for_success(self, message):
        """Specify action is completed with a success status

        :param message: custom message
        :type message: str
        """
        logger.debug("Nothing to do for 'close_for_success' tracking default implementation.")
