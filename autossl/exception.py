import json


class AutoSslException(Exception):
    """Generic exception for autossl

    Allow to chain exceptions keeping track of origin exception
    """
    def __init__(self, msg, original_exception=None):
        message = msg
        if original_exception:
            message += ": %s" % original_exception
        super(AutoSslException, self).__init__(message)
        self.__cause__ = original_exception
        self.__suppress_context__ = True


class HttpCodeException(AutoSslException):
    def __init__(self, request_exception):
        """Exception raised when received Http response has an invalid http code

        :param request_exception: requests HTTP exception
        :type request_exception: requests.exceptions.HTTPError
        """
        try:
            response_body_json = request_exception.response.json()
            response_body_text = json.dumps(response_body_json, indent=4, sort_keys=True)
        except ValueError:
            response_body_json = None
            response_body_text = request_exception.response.text
        exception_message = "HTTPError: => %s %s : %s" % (request_exception.request.method,
                                                          request_exception.request.url,
                                                          response_body_text)
        super(HttpCodeException, self).__init__(exception_message, original_exception=request_exception)
        self.status_code = request_exception.response.status_code
        self.response_body_text = response_body_text
        self.response_body_json = response_body_json


class NotFound(AutoSslException):
    """Requested data not found"""
    pass


class SslBlueprintInconsistency(AutoSslException):
    """SSL blueprint definition contains inconsistencies"""
    pass


class InvalidCertificate(AutoSslException):
    """Certificate is not matching expected criteria"""
    pass


class InvalidTrustChain(InvalidCertificate):
    """Certificate is not compatible with CA certificate specified"""
    pass


class KeyMismatch(InvalidCertificate):
    """Certificate does not match private key"""
    pass


class ExpiredCertificate(InvalidCertificate):
    """Certificate is expiring"""
    pass


class DefinitionMismatch(InvalidCertificate):
    """Certificate is not matching blueprint definition"""
    pass


class CertificateNotFound(NotFound):
    """Requested certificate not present on server"""
    pass


class DeployCertificateError(AutoSslException):
    """Unexpected error when trying to deploy new certificate"""
    pass
