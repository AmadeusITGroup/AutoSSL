import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from acme import challenges
from acme import client
from acme import errors
from acme import messages
import josepy as jose

from .. import ssl, util, exception
from . import base


USER_AGENT = 'python-autossl'

logger = logging.getLogger(__name__)


class AcmeHttp01(base.CaManager):

    def __init__(self, ca_config, staging=True, storage_api=None, **kwargs):
        super(AcmeHttp01, self).__init__(ca_config, staging=staging, storage_api=storage_api)
        self.ca_api = ca_config.get_acme_api(staging=self.staging)
        self.contact_email = ca_config.ca_config.get('contact_email')

        self.account_key = None
        self.servers_api = []

    def get_signed_certificate(self, ssl_blueprint=None, csr_path=None, servers_api=None):
        self.servers_api = servers_api

        with util.TempDir() as temp_folder:
            # retrieve CA account key from storage
            ca_account_key_content = self.storage_api.retrieve_data(
                name=self.ca_config.ca_config['storage']['name'],
                data_type=ssl.DataType.PrivateKey,
            )
            self.account_key = temp_folder.path / 'ca_account.key'
            self.account_key.write_bytes(ca_account_key_content)

            client_acme = self._get_or_create_account()

            # Request new certificate order for specified CSR
            order_resource = client_acme.new_order(csr_pem=csr_path.read_text())

            # signed certificate ready to be used
            pem_signed_certificate = self._perform_http01(client_acme, order_resource)

        # return PEM certificate (bytes)
        return pem_signed_certificate.encode('utf-8')

    @property
    def is_automated_renewal_supported(self):
        return True

    def _get_or_create_account(self):
        """Register account if not already done, else just return ACME client updated with existing account"""
        logger.info("Registering account...")

        ca_key = serialization.load_pem_private_key(
            data=self.account_key.read_bytes(),
            password=None,
            backend=default_backend(),
        )
        acc_key = jose.JWKRSA(key=ca_key)

        # Register account and accept TOS
        client_network = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
        directory = messages.Directory.from_json(client_network.get(self.ca_api + '/directory').json())
        client_acme = client.ClientV2(directory=directory, net=client_network)

        try:
            # Creates account with contact information.
            # Terms of Service URL is in client_acme.directory.meta.terms_of_service
            client_acme.new_account(
                messages.NewRegistration.from_data(
                    email=self.contact_email,
                    terms_of_service_agreed=True,
                )
            )
            logger.info("New account successfully created!")
        except errors.ConflictError:
            logger.info("Account already registered!")
            # retrieve existing account information
            account_registration = messages.NewRegistration(key=acc_key.public_key(), only_return_existing=True)

            # TODO migrate to public API when available in ACME module
            #  reproduce code of client_acme.new_account but without throwing exception when account already exists
            response = client_acme._post(directory['newAccount'], account_registration)
            account_info = client_acme._regr_from_response(response)

            # assign registration information to existing client
            client_acme.net.account = account_info
        return client_acme

    @staticmethod
    def _get_http01_challenge(authz):
        """Extract HTTP01 challenge from authorization resource."""
        # authz.body.challenges is a set of ChallengeBody objects.
        for challenge_body_item in authz.body.challenges:
            # Find HTTP01 challenge for each domain to validate
            if isinstance(challenge_body_item.chall, challenges.HTTP01):
                return challenge_body_item
        raise exception.AutoSslException('HTTP-01 challenge was not offered by the CA server.')

    def _deploy_challenge(self, client_acme, authz):
        """Deploy challenge token on all servers and warn CA server that it can start validation"""
        challenge_body = self._get_http01_challenge(authz)
        response, validation = challenge_body.response_and_validation(client_acme.net.key)
        token = challenge_body.chall.encode('token')
        logger.info("Deploy challenge for domain {}".format(authz.body.identifier.value))
        try:
            # deploy challenge on servers
            for server_api in self.servers_api:
                server_api.create_acme_challenge(
                    token=token,
                    key_authorization=validation,
                )

            # Let the CA server know that we are ready for this challenge validation
            client_acme.answer_challenge(challenge_body, response)

        except Exception:
            # cleanup challenge in case of any exception, to avoid leaking tokens on servers
            self._cleanup_challenges(token=token)
            raise

        return token

    def _cleanup_challenges(self, token):
        """Remove specified challenge token from all servers"""
        for server_api in self.servers_api:
            server_api.delete_acme_challenge(token=token)

    def _perform_http01(self, client_acme, order_resource):
        """Set up challenge on servers and perform HTTP-01 challenge verification."""

        # keep track of all tokens successfully deployed to be able to clean them up at the end
        tokens = []
        try:
            # Deploy token/validation for HTTP-01 challenge
            for authz in order_resource.authorizations:
                tokens.append(self._deploy_challenge(client_acme, authz))

            # Wait for challenge status and then issue a certificate.
            finalized_order_resource = client_acme.poll_and_finalize(order_resource)
        finally:
            # cleanup all challenges from servers once all validation is done
            for token in tokens:
                self._cleanup_challenges(token=token)

        # return certificate
        return finalized_order_resource.fullchain_pem
