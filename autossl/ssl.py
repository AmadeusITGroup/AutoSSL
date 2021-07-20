import datetime
from enum import Enum
import logging
import os
import re
import tempfile
import uuid

# external packages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
import yaml

from . import credential, exception, util

logger = logging.getLogger(__name__)


class DataType(Enum):
    """list of data types supported"""
    CertificateSigningRequest = 'csr'
    PrivateKey = 'key'
    Certificate = 'crt'
    Blueprint = 'yaml'


class SslBlueprint(object):
    def __init__(self, yaml_path=None, global_config_path=None):
        """Blueprint representation of an SSL certificate

        :param yaml_path: path to the yaml file representing the blueprint
        :type yaml_path: pathlib.Path or str
        :param global_config_path: path to the yaml file representing the global configuration
        :type global_config_path: pathlib.Path
        """
        blueprint_content = dict()
        self.blueprint_path = None

        if yaml_path:
            # also support str path in input
            if not isinstance(yaml_path, util.Path):
                yaml_path = util.Path(yaml_path)
            with yaml_path.open() as blueprint_file:
                blueprint_content = yaml.safe_load(blueprint_file)
            self.blueprint_path = yaml_path

        if global_config_path:
            # also support str path in input
            if not isinstance(global_config_path, util.Path):
                global_config_path = util.Path(global_config_path)
            with global_config_path.open() as global_config_path_file:
                global_config_content = yaml.safe_load(global_config_path_file)

            # all keys present in global config and not in blueprint will be added
            for key in global_config_content:
                if key not in blueprint_content:
                    blueprint_content[key] = global_config_content[key]

            # create local temporary file with global config
            with tempfile.NamedTemporaryFile(delete=False, mode='w+') as consolidated_blueprint_file:
                self.consolidated_blueprint_path = util.Path(consolidated_blueprint_file.name)
                yaml.dump(data=blueprint_content, stream=consolidated_blueprint_file)
        else:
            self.consolidated_blueprint_path = self.blueprint_path

        # ## mandatory fields
        # name of certificate on server
        self.name = blueprint_content.get('name')

        # list of servers where certificate must be deployed
        self.servers = blueprint_content.get('servers', [])

        #########################
        # certificate information
        #########################
        self.certificate = None
        self.ca_config = None
        if blueprint_content.get('certificate'):
            self.certificate = SslCertificateConfig(
                # Certificate type
                certificate_type=blueprint_content['certificate'].get('type'),
                # which CA to use for renewal
                certificate_authority=blueprint_content['certificate'].get('certificate_authority'),
            )
            # to specify if certificate on server must exactly match the content of the blueprint
            self.certificate.set_attr_if_not_none(
                'exact_match',
                blueprint_content['certificate'].get('exact_match')
            )

            # force reuse of existing private key if available in storage, else generate a new one
            self.certificate.set_attr_if_not_none(
                'private_key_reuse',
                blueprint_content['certificate'].get('private_key_reuse')
            )

            self.certificate.set_attr_if_not_none(
                'private_key_size',
                blueprint_content['certificate'].get('private_key_size')
            )

            # Organization information
            # get first information from blueprint directly from certificate blueprint
            # or get it from global config
            self.certificate.set_attr_if_not_none(
                'organization',
                blueprint_content['certificate'].get('organization') or blueprint_content.get('organization')
            )

            # Common Name field of the certificate
            self.certificate.set_attr_if_not_none(
                'common_name',
                blueprint_content['certificate'].get('common_name')
            )

            # List of SAN for this certificate
            self.certificate.set_attr_if_not_none(
                'sans',
                blueprint_content['certificate'].get('san')
            )

            # renew certificate if less than `renewal_delay` days before expiration
            self.certificate.set_attr_if_not_none(
                'renewal_delay',
                blueprint_content['certificate'].get('renewal_delay')
            )

            # chain_of_trust associated to server certificate
            self.certificate.set_attr_if_not_none(
                'chain_of_trust',
                blueprint_content['certificate'].get('chain_of_trust')
            )

            # this certificate will be use to sign other certificates (CA)
            self.certificate.set_attr_if_not_none(
                'is_ca',
                blueprint_content['certificate'].get('is_ca')
            )

            self.ca_config = CertificateAuthorityConfig(
                certificate_authorities=blueprint_content.get('certificate_authorities'),
                certificate_authority_key=self.certificate.certificate_authority,
            )

        # retrieve storage and tracking server configuration
        self.storage = blueprint_content.get('storage')
        self.tracking = blueprint_content.get('tracking')
        self.credentials = blueprint_content.get('credentials')

        # perform extended validation of blueprint content
        self.validate()

    def __del__(self):
        # cleanup temporarily generated consolidated config file if present
        if hasattr(self, 'consolidated_blueprint_path') \
                and hasattr(self, 'blueprint_path') \
                and self.consolidated_blueprint_path.is_file() \
                and self.consolidated_blueprint_path != self.blueprint_path:
            self.consolidated_blueprint_path.unlink()

    def validate(self):
        """Validate data extracted from blueprint

        :raise ValueError: if content of specified blueprint is not valid
        """
        # check certificate information
        if self.certificate:
            self.certificate.validate(ca_config=self.ca_config)

        # validate server config
        for server in self.servers:
            server_credentials_name = server.get('credentials')
            if server_credentials_name is not None:
                # check all server credentials are referenced in global section
                if server_credentials_name not in self.credentials:
                    raise ValueError("Missing credentials {} in global credentials section"
                                     .format(server_credentials_name))

                # check 'type' attribute is present and with a valid value in global credentials section
                credential_type = self.credentials[server_credentials_name].get('type')
                try:
                    credential.CredentialType[credential_type]
                except KeyError:
                    raise ValueError("Credential type {} not supported, expected one of {}"
                                     .format(credential_type, str(credential.CredentialType.__members__.keys())))

    @property
    def domains(self):
        """Get domains covered by this blueprint

        :return: list of domains in blueprint
        :rtype: set
        """
        return self.certificate.domains

    def get_config(self, name, path=None, default=None):
        result = getattr(self, name)
        if path is not None and any(path):
            # no config specified, use base one
            if result is None:
                if len(path) == 1 and path[0] == 'type':
                    # just use base implementation
                    return 'base.{}'.format(name.title())
            else:
                for key in path:
                    if result is None:
                        break
                    result = result.get(key)
        if result is None:
            result = default
        return result

    def get_chain_of_trust(self):
        """Return list of certificates to have full chain of trust: intermediate, root
        :return: list of certificates starting intermediate until root certificate
        :rtype: list
        """
        # chain of trust can be define directly in certificate config
        # or globally at CA config level
        return self.certificate.chain_of_trust or self.ca_config.get_chain_of_trust()


class SslCertificateConfig(object):
    def __init__(self, certificate_type, certificate_authority,
                 common_name=None, sans=None, organization=None, chain_of_trust=None,
                 exact_match=False, private_key_reuse=True, private_key_size=4096,
                 renewal_delay=30, is_ca=False):
        """

        :param certificate_type: ssl certificate type (DV, OV, EV)
        :param certificate_authority: certificate authority name
        :param common_name: ssl certificate common name
        :param sans: ssl certificate alternative name
        :param organization: certificate organization
        :param chain_of_trust: list of certificates to have full chain of trust: intermediate, root
        :param exact_match: to specify if certificate on server must exactly match the content of the blueprint
        :param private_key_reuse: force reuse of existing private key if available in storage, else generate a new one
        :param private_key_size: size of private key if new one must be generated
        :param renewal_delay: renew certificate if less than `renewal_delay` days before expiration
        :param is_ca: this certificate is used to sign other certificates (CA)
        """
        # Mandatory fields
        self.certificate_type = certificate_type
        self.certificate_authority = certificate_authority

        # Optional fields
        self.common_name = common_name
        self.sans = sans or []
        self.organization = organization
        self.chain_of_trust = chain_of_trust or []

        self.exact_match = exact_match
        self.private_key_reuse = private_key_reuse
        self.private_key_size = private_key_size
        self.renewal_delay = renewal_delay
        self.is_ca = is_ca

    @property
    def domains(self):
        # build unique list of domains that is expected to be covered
        return get_domains(common_name=self.common_name, sans=self.sans)

    def set_attr_if_not_none(self, attr_name, value):
        """Set attribute value if value is not None

        :param attr_name: attribute name
        :type attr_name: str
        :param value: attribute value
        """
        if value is not None:
            setattr(self, attr_name, value)

    def validate(self, ca_config):
        if self.certificate_type != 'DV':
            # mandatory for non DV certificates
            if self.organization is None:
                raise ValueError('Missing mandatory organization information for certificate type %s'
                                 % self.certificate_type)

        # a certificate must cover at list 1 domain, so we expect either common name or san or both
        if self.common_name is None and len(self.sans) == 0:
            raise ValueError("At least 1 of attributes 'common_name' or 'san' must be provided")

        # validate format of domains specified
        domain_pattern = r'^(\*\.)?[-\.\w+]{1,255}$'
        if self.common_name:
            if not re.match(domain_pattern, self.common_name):
                raise ValueError("Specified common name '{}' does not match pattern '{}'"
                                 .format(self.common_name, domain_pattern))

        for san in self.sans:
            if not re.match(domain_pattern, san):
                raise ValueError("Specified san '%s' does not match pattern '%s'" % (san, domain_pattern))

        if not isinstance(self.renewal_delay, int):
            raise ValueError("Renewal delay must be an integer got %s" % type(self.renewal_delay))

        if ca_config and not ca_config.is_certificate_supported(cert_type=self.certificate_type):
            raise ValueError('Certificate type %s not supported. Expect one of [%s].'
                             % (self.certificate_type,
                                ', '.join(ca_config.get_supported_certificate_types())))


class CertificateAuthorityConfig(object):
    def __init__(self, certificate_authorities, certificate_authority_key):
        """Config representing CA configuration"""
        self.ca_config = dict()

        # find config for specified CA or raise an exception
        if certificate_authorities is not None:
            for ca_config in certificate_authorities:
                if ca_config.get('key') == certificate_authority_key:
                    self.ca_config = ca_config
                    break
            else:
                raise ValueError("Certificate authority '%s' is not supported. Expect one of [%s]."
                                 % (certificate_authority_key,
                                    ', '.join([ca_config.get('key') for ca_config in certificate_authorities])))

    def get_supported_certificate_types(self):
        """Get list of certificate types currently supported by CA

        :return: list of certificate types currently supported by CA
        :rtype: list
        """
        # if not restricted explicitly, support all certificates types by default
        return self.ca_config.get('certificate_types', ['DV', 'OV', 'EV'])

    def is_certificate_supported(self, cert_type):
        """Check if specified certificate type is supported by CA

        :param cert_type: type of certificate to check (ex: DV)
        :type cert_type: str
        :return: True if CA supports this certificate type
        :rtype: bool
        """
        return cert_type in self.get_supported_certificate_types()

    def is_acme_supported(self):
        """Check if CA supports ACME protocol

        :return: True if CA supports ACME protocol
        :rtype: bool
        """
        return any(self.ca_config.get('acme_api', {}))

    def get_acme_api(self, staging=False):
        acme_apis = self.ca_config.get('acme_api', {})
        if staging:
            return acme_apis.get('staging')
        else:
            return acme_apis.get('production')

    def get_storage_config(self):
        """Get configuration of CA storage api

        :return: CA storage configuration
        :rtype: dict
        """
        return self.ca_config.get('storage')

    def get_chain_of_trust(self):
        """Return list of certificate to have full chain of trust: intermediate, root
        :return: list of certificate starting intermediate until root certificate
        :rtype: list
        """
        return self.ca_config.get('chain_of_trust') or []


def generate_csr(name,
                 common_name=None,
                 company_name=None,
                 street_address=None,
                 city=None,
                 state=None,
                 postal_code=None,
                 country_code=None,
                 email_address=None,
                 sans=None,
                 key_content=None,
                 key_size=4096,
                 output_path=None,
                 is_ca=False):
    """Generate a CSR for specified parameters

    if a private key is given, it will be used to generate CSR, else a new one will be created

    :param name: name of file generated (without extension)
    :param common_name: common name
    :param company_name: company name
    :param street_address: company street address
    :param city: company city
    :param state: company state
    :param postal_code: company postal code
    :param country_code: company country
    :param email_address: contact email
    :param sans: list of SANs to be covered
    :param key_content: optional private key content to generate CSR
    :type key_content: byte
    :param key_size: size of private key to generate CSR, if no key in input
    :param output_path: local path where to generate files
    :param is_ca: True if the requested certificate is for a CA
    :return: tuple(key_content, csr_path) with content of private key and path to csr file
    :rtype: tuple(bytes, pathlib.Path)
    """
    output_path = output_path or os.path.curdir
    if not isinstance(output_path, util.Path):
        output_path = util.Path(str(output_path))
    output_path.mkdir(parents=True, exist_ok=True)

    # use existing private key
    if key_content is not None:
        key = serialization.load_pem_private_key(
            data=key_content,
            password=None,
            backend=default_backend(),
        )
        logger.info("Using existing private key.")
    # Generate our key
    else:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        # get private key content as we never want to write it on disk for security reasons
        key_content = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        logger.info("New private key created.")

    name_attributes = []

    if common_name is not None:
        name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, u"%s" % common_name))
    if company_name is not None:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"%s" % company_name))
    if street_address is not None:
        name_attributes.append(x509.NameAttribute(NameOID.STREET_ADDRESS, u"%s" % street_address))
    if postal_code is not None:
        name_attributes.append(x509.NameAttribute(NameOID.POSTAL_CODE, u"%s" % postal_code))
    if state is not None:
        name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"%s" % state))
    if city is not None:
        name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, u"%s" % city))
    if country_code is not None:
        name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, u"%s" % country_code))
    if email_address is not None:
        name_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, u"%s" % email_address))

    # Generate a CSR
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name(name_attributes))
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"%s" % alt_domain) for alt_domain in sans or []]),
        critical=False
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
                ),
            critical=True,
        )
        if sans:
            builder = builder.add_extension(
                x509.NameConstraints([x509.DNSName(u"%s" % alt_domain) for alt_domain in sans], []), critical=True
            )

    # Sign the CSR with our private key.
    csr = builder.sign(key, hashes.SHA256(), default_backend())

    # Write our CSR out to disk.
    csr_path = output_path.joinpath("%s.csr" % name)
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    logger.info("Csr %s created." % csr_path.name)

    return key_content, csr_path


def sign(csr, ca_key, ca_cert, validity_days):
    """Sign a certificate request with a key (CA)

    :param csr: certificate request to sign
    :type csr: bytes, PEM encoded
    :param ca_key: the signing key
    :type ca_key: bytes, PEM encoded
    :param ca_cert: the signing certificate
    :type ca_cert: bytes, PEM encoded
    :param validity_days: certificate validity duration (in days)
    :type validity_days: int
    :return: the signed certificate
    :rtype: bytes, PEM encoded
    """
    csr = x509.load_pem_x509_csr(data=csr, backend=default_backend())
    ca_key = serialization.load_pem_private_key(
        data=ca_key,
        password=None,
        backend=default_backend(),
    )
    ca_crt = x509.load_pem_x509_certificate(data=ca_cert, backend=default_backend())

    now = datetime.datetime.utcnow()
    builder = x509.CertificateBuilder() \
        .subject_name(csr.subject) \
        .issuer_name(ca_crt.subject) \
        .public_key(csr.public_key()) \
        .serial_number(uuid.uuid4().int) \
        .not_valid_before(now) \
        .not_valid_after(now + datetime.timedelta(days=validity_days)) \
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    crt = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    return crt.public_bytes(encoding=serialization.Encoding.PEM)


def get_domains_from_x509(file_path, file_type):
    """Retrieve the list of domains covered by specified x509 file (CSR or CRT)

    :param file_path: path to x509 file
    :type file_path: pathlib.Path
    :param file_type: type of x509 file.
        Supported types: [DataType.CertificateSigningRequest, DataType.Certificate]
    :type file_type: DataType
    :return: list of domain
    :rtype: set
    """
    domains = set()

    # load csr first
    if file_type == DataType.CertificateSigningRequest:
        x509_object = x509.load_pem_x509_csr(data=file_path.read_bytes(), backend=default_backend())
    elif file_type == DataType.Certificate:
        x509_object = x509.load_pem_x509_certificate(data=file_path.read_bytes(), backend=default_backend())
    else:
        raise ValueError("x509 file type specified not supported: ''" % file_type)

    # common_name (optional, we can have only sans)
    common_name = x509_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_name) > 0:
        domains.add(common_name[0].value)

    # sans
    try:
        for dns_name in x509_object.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value:
            domains.add(dns_name.value)
    except ExtensionNotFound:
        # no san in that CSR
        pass

    return domains


def get_expiration(crt_path):
    x509_object = x509.load_pem_x509_certificate(data=crt_path.read_bytes(), backend=default_backend())
    return x509_object.not_valid_after


def check_certificate_with_key(key_path, crt_path):
    """Check whether a private key matches a certificate

    For this, we compare RSAPublicNumbers from public key in certificate
    with the RSAPublicNumbers which makes up the RSA public key associated with this RSA private key.

    :param key_path: path to private key
    :type key_path: pathlib.Path
    :param crt_path: path to SSL certificate
    :type crt_path: pathlib.Path
    :return: True, if certificate matches private key
    :rtype: bool
    """
    # load private key
    key = serialization.load_pem_private_key(
        data=key_path.read_bytes(),
        password=None,
        backend=default_backend())

    # load certificate
    certificate = x509.load_pem_x509_certificate(
        data=crt_path.read_bytes(),
        backend=default_backend())

    return key.private_numbers().public_numbers == certificate.public_key().public_numbers()


def check_chain_of_trust(chain_of_trust, crt_path):
    """Check that input certificate matches chain of trust

    :param chain_of_trust: list of certificates of the chain of trust (intermediate CA, root CA)
    :type chain_of_trust: list
    :param crt_path: local path to certificate to verify
    :type crt_path: pathlib.Path
    :raises exception.InvalidTrustChain: if input certificate does not match chain of trust specified
    """
    with util.TempDir() as temp_folder:
        # temporarily write CA information in bundle file
        bundle_path = temp_folder.path.joinpath(str(crt_path) + '.bundle')
        bundle_path.write_bytes('\n'.join(chain_of_trust).encode('utf-8'))

        # verify directly with openssl as unable to find a way with cryptography module
        if os.system('openssl verify -CAfile {} {}'.format(bundle_path, crt_path)) != 0:
            raise exception.InvalidTrustChain(
                "Certificate {} does not match CA certificate specified".format(crt_path.name))


def is_domain_matching(domain_to_check, reference_domain, exact_match=False):
    r"""Check if a domain is matching another domain

    For example, test.example.com is matching by \*.example.com

    :param domain_to_check: the domain to check
    :param reference_domain: the reference domain to compare with
    :param exact_match: If True, domain_to_check and reference_domain must be the same
        If False, domain_to_check can be only a subset of reference_domain
    :return: True if domain_to_check is matching reference_domain
    :rtype: bool
    """
    if domain_to_check == reference_domain:
        return True
    elif not exact_match:
        # use regexp to support wildcard domain
        regex = reference_domain.replace('.', r'\.').replace('*', r'.*') + '$'
        if re.match(regex, domain_to_check):
            return True
    return False


def is_domain_list_matching(domains_to_check, reference_domains, exact_match=False):
    r"""Check if a list of domains are covered by another list of domains

    For example, test.example.com and test2.example.com are covered by \*.example.com

    :param domains_to_check: list of domains to check
    :param reference_domains: list of reference domains to compare with
    :param exact_match: If True, domains_to_check and reference_domains must be the same
        If False, domains_to_check can be only a subset of reference_domains
    :return: True if domains_to_check are covered by reference_domains
    :rtype: bool
    """
    domains_not_covered = set()
    for domain_to_check in domains_to_check:
        for reference_domain in reference_domains:
            if is_domain_matching(domain_to_check, reference_domain, exact_match=exact_match):
                break
        else:
            domains_not_covered.add(domain_to_check)

    if any(domains_not_covered):
        logger.info("Following domains not covered by certificate: [%s]" % (', '.join(domains_not_covered)))
        return False
    logger.debug("Blueprint domains all covered by current certificate")
    return True


def get_domains(common_name=None, sans=None):
    """Get unique list of domains for input criteria

    :param common_name: Certificate common name
    :type common_name: str or None
    :param sans: Certificate SANs List
    :type sans: list(str) or None
    :return: unique list of domains
    :rtype: set(str)
    """
    domains = set()
    if common_name is not None:
        domains.add(common_name)
    if sans:
        domains |= set(sans)
    return domains


class SslCertificate(object):
    def __init__(self, x509_path=None, common_name=None, sans=None, expiration=None):
        self.common_name = common_name
        self.sans = sans or []
        self.expiration = expiration

        if x509_path:
            self.init_from_x509(x509_path)

    def __eq__(self, other):
        return self.common_name == other.common_name \
               and sorted(self.sans) == sorted(other.sans) \
               and self.expiration == other.expiration

    def __ne__(self, other):
        return not self.__eq__(other)

    def init_from_x509(self, x509_path):
        """
        :param x509_path: path to PEM certificate
        :type x509_path: pathlib.Path
        """
        if not isinstance(x509_path, util.Path):
            x509_path = util.Path(str(x509_path))
        x509_object = x509.load_pem_x509_certificate(data=x509_path.read_bytes(), backend=default_backend())

        # common_name (optional, we can have only sans)
        common_name = x509_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(common_name) > 0:
            self.common_name = common_name[0].value

        # sans
        try:
            for dns_name in x509_object.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value:
                self.sans.append(dns_name.value)
        except ExtensionNotFound:
            # no san in that certificate
            pass

        self.expiration = x509_object.not_valid_after
        return self

    def is_expired(self, expiration_delay=0):
        """Check for expiration

        :param expiration_delay: Number of days before real expiration we consider a renewal needed
        :type expiration_delay: int
        :return: True is certificate is going to expire in less than expiration_delay days
        :rtype: bool
        """
        status = 'valid'
        now = datetime.datetime.utcnow()
        if self.expiration < now:
            status = 'expired'
        else:
            status += ' (%s days remaining)' % (self.expiration.date() - now.date()).days
        logger.info("{0} - {1} => {2}".format(
            self.common_name, self.expiration.isoformat(), status))
        return (self.expiration.date() - now.date()).days <= expiration_delay

    def is_same(self, common_name=None, sans=None, exact_match=False):
        """Check if current certificate is covering all specified domains

        :param common_name: Common name
        :type common_name: str
        :param sans: list of Subject Alternate Names
        :type sans: list
        :param exact_match: if True, certificate must exactly match input domains
            if False, input domain will also match wilcard certificate and additional domains in certificate will
            be ignored
        :type exact_match: bool
        :return: True is certificate is already covering all domains
        """

        # build unique list of domains that is expected to be covered
        input_domains = get_domains(common_name=common_name, sans=sans)

        # check if some domains are missing
        return is_domain_list_matching(
            domains_to_check=input_domains,
            reference_domains=self.domains,
            exact_match=exact_match,
        )

    @property
    def domains(self):
        # build unique list of domains that is expected to be covered
        return get_domains(common_name=self.common_name, sans=self.sans)
