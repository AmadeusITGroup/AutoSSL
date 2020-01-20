import datetime
import json
import logging
import os
import yaml

from .. import exception, ssl
from . import base

logger = logging.getLogger(__name__)


class LocalFileTracking(base.Tracking):

    def __init__(self, ssl_blueprint_path, log_folder, **kwargs):
        r"""Track actions in a log file on local file system

        :param ssl_blueprint_path: local path to ssl blueprint
        :type ssl_blueprint_path: pathlib.Path
        :param \**kwargs: generic key/value parameters
        :type \**kwargs: dict
        """
        super(LocalFileTracking, self).__init__(ssl_blueprint_path=ssl_blueprint_path, **kwargs)

        # validate input blueprint
        self.ssl_blueprint = ssl.SslBlueprint(yaml_path=self.ssl_blueprint_path)

        # build log file path from blueprint name
        self.log_file_path = '{}.log'.format(os.path.join(os.path.expandvars(log_folder), self.ssl_blueprint.name))

    def __write_log(self, content, name=None, data_type=None):
        structured_content = {
            'timestamp': datetime.datetime.utcnow().strftime('%Y/%d/%m %I:%M:%S %p'),
            'name': name or 'log',
            'content': os.path.expandvars(content),
        }
        if data_type is not None:
            structured_content['data_type'] = data_type.value

        with open(self.log_file_path, 'a') as log_file:
            json.dump(structured_content, log_file, sort_keys=True)
            log_file.write('\n')

    def create(self, tracking_type, servers=None):
        """Create a tracking record with details of current SSL blueprint

        :param tracking_type: Type of tracking. Can be used to customized tracking record content.
        :type tracking_type: TrackingType
        :param servers: List of servers in scope of the action. All servers from config if None specified here.
        :type servers: list
        :return: Identifier for the created record
        :rtype: str
        """
        message = ''
        if tracking_type == base.TrackingType.Renewal:
            message = """Creation of the following certificate requested:

              - Certificate Authority (CA): {certificate_authority}
              - Server type: {server_type}
              - Certificate Type: {certificate_type}
              - Common_name: {common_name}
              - Subject Alternate Name: {sans}
             """.format(
                certificate_authority=self.ssl_blueprint.certificate.certificate_authority,
                server_type=', '.join(set(server['type'] for server in self.ssl_blueprint.servers)),
                certificate_type=self.ssl_blueprint.certificate.certificate_type,
                common_name=self.ssl_blueprint.certificate.common_name or '',
                sans=', '.join(self.ssl_blueprint.certificate.sans),
            )
        elif tracking_type == base.TrackingType.Synchronize:
            message = """Some servers have a missing or outdated SSL certificate for:
              - Certificate Authority (CA): {certificate_authority}
              - Certificate Type: {certificate_type}
              - Common_name: {common_name}
              - Subject Alternate Name: {sans}

            Valid certificate is already available and will be deployed on the following servers:{servers}
            """.format(
                certificate_authority=self.ssl_blueprint.certificate.certificate_authority,
                certificate_type=self.ssl_blueprint.certificate.certificate_type,
                common_name=self.ssl_blueprint.certificate.common_name or '',
                sans=', '.join(self.ssl_blueprint.certificate.sans),
                servers=yaml.dump(data=servers or [], indent=2, default_flow_style=False),
            )
        self.update(message=message)

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
        if local_path:
            content = local_path.read_bytes()
        self.__write_log(content=content.decode('utf-8'), name=name, data_type=data_type)

    def update(self, message):
        """Update tracking record

        :param message: text to add to tracking record
        :type message: str
        """
        self.__write_log(message)

    def refresh(self, record_id):
        """Update current tracking instance with last changes from tracking record on server side

        :param record_id: identifier of the record to refresh
        """
        logger.info("Nothing to do for 'refresh' LocalFileLogging implementation.")

    def retrieve_data(self, name=None, data_type=None, **kwargs):
        r"""Retrieve specified data from tracking system

        :param name: Name of file/data to retrieve
        :type name: str
        :param data_type: type of data to retrieve
        :type data_type: ssl.DataType
        :param \**kwargs: generic key/value parameters
        :type kwargs: dict
        :return: file content
        :rtype: byte
        """
        if name is None and data_type is None:
            raise ValueError("Either name or data_type must be provided, none given.")

        if os.path.isfile(self.log_file_path):
            with open(self.log_file_path, 'r') as log_file:
                # search data from the end to get most accurate one
                # this works fine as this log file is expected to be small enough to fit in memory
                for raw_line in reversed(log_file.readlines()):
                    json_line = json.loads(raw_line)
                    if (name and name == json_line.get('name')) or \
                            (data_type and data_type.value == json_line.get('data_type')):
                        return json_line['content'].encode('utf-8')
        error_message = 'No data found.'
        if name:
            error_message = "No data found with name '{}'".format(name)
        elif data_type:
            error_message = "No data found for file of type '{}'".format(data_type.name)
        raise exception.NotFound(error_message)

    def close_for_failure(self, message):
        """Specify action is completed with a failed status

        :param message: custom message
        :type message: str
        """
        self.__write_log(message)

    def close_for_success(self, message):
        """Specify action is completed with a success status

        :param message: custom message
        :type message: str
        """
        self.__write_log(message)
