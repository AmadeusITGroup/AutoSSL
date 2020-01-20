
class Storage(object):

    def __init__(self, tracking_record_id=None, **kwargs):
        r"""Base interface to store data

        :param tracking_record_id: identified of tracking record if tracking system is used
        :type tracking_record_id:
        :param \**kwargs: key/value parameters needed for initialization
        :type \**kwargs: dict
        """
        self.tracking_record_id = tracking_record_id

    def save_data(self, name, data_type, content=None, local_path=None, **kwargs):
        r"""Save specified content in storage

        :param name: name of the content to be stored on server side
        :type name: str
        :param data_type: type of data to save
        :type data_type: ssl.DataType
        :param content: content to be stored on server side
        :type content: bytes
        :param local_path: local path to a file to store
        :type local_path: pathlib.Path or str
        :param \**kwargs: optional key/value parameters from blueprint to save data
        :type \**kwargs: dict

        Either one of `content` or `local_path` must be specified but not both
        """
        raise NotImplementedError("Must be overridden in storage specific implementation.")

    def retrieve_data(self, name, data_type, **kwargs):
        r"""Retrieve data from storage

        :param name: identifier of data to retrieve
        :type name: str
        :param data_type: type of data to retrieve
        :type data_type: ssl.DataType
        :param \**kwargs: optional key/value parameters from blueprint to retrieve data
        :type \**kwargs: dict
        :return: requested data
        :rtype: bytes
        :raise exception.NotFound: when requested data are missing in storage
        """
        raise NotImplementedError("Must be overridden in storage specific implementation.")
