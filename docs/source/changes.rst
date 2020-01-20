Changes
=======

0.9.0 (20/01/2020)
---------------------
- First public release
- ACMEv1 support removed (v1 is deprecated since quite some time and will be disabled for new domains in June 2020)

0.8.0 (09/01/2020)
---------------------
- [Feature] support for ACMEv2 HTTP01 challenge
- [Feature] ability to read credentials from environment variables
- [Improvement] migrate from simple string path to pathlib for easier path manipulation
- [Improvement] use byte as default encoding rather than str to avoid useless conversions
- [Improvement] use relative imports
- [Improvement] add missing doc

0.7.5 (16/12/2019)
---------------------
- [Bug] ACME http01 - CA account key was deleted too early in the process while was still needed for renewal

0.7.4 (12/12/2019)
---------------------
- [Improvement]: move acme section from blueprint directly in CA configuration
- [Improvement]: remove dedicated acme_storage and only use 1 generic storage class for CA manager

0.7.3 (11/12/2019)
---------------------
- [Improvement]: avoid leaking credentials in git storage logs

0.7.2 (06/12/2019)
---------------------
- [Bug]: fix invalid attribute in acme_v1_http01 renewal

0.7.1 (05/12/2019)
---------------------
- [Bug]: fix module import on initialization

0.7.0 (05/12/2019)
---------------------
- [Improvement]: generic CA managers for automatic certificate renewal, the type is determined from `type` attribute in blueprint CA. Supported values are : `autossl.ca_manager.acme_v1_http01.AcmeHttp01` and `autossl.ca_manager.local.LocalCa`
- [Feature]: certificate signing from a CA key/certificate available in storage

0.6.0 (29/11/2019)
---------------------
- [Feature]: support deployment of full certificate chain on any type of server
- [Feature]: when chain of trust is specified (in global config or ssl blueprint) always verify it before deployment

0.5.6 (19/11/2019)
---------------------
- [Bug]: to_be_renewed flag returned by `manager.get_renewal_status` was still true when stored certificate was valid if at least 1 server was invalid
- [Feature]: `manager.get_and_check_artifacts` ability to try first retrieving artifacts from tracking when tracking ID specified, as we consider tracking the most up to date in that case

0.5.5 (18/11/2019)
---------------------
- [Feature] support for CA certificates request

0.5.4 (12/11/2019)
---------------------
- [Improvement]: python 3.8 support
- [Bug]: credentials in input of storage.gitscm were ignored, directly add them in input git url for http

0.5.3 (12/11/2019)
---------------------
- DO NOT USE

0.5.2 (06/11/2019)
---------------------
- [Bug]: fix equality operator on SslCertificate object as sans comparison must ignore sorting
- [Bug]: do not directly compare certificates in SslManager and always call 'is_same' from Server api as each server can customize/override its behavior

0.5.1 (29/10/2019)
---------------------
- [Technical]: no change

0.5.0 (14/10/2019)
---------------------
- [Improvement]: support certificates without servers

0.4.4 (22/08/2019)
---------------------
- [Bug]: chain of trust in global config was ignored
- [Feature] add retries in case Incapsula return internal error at deployment (as happening quite often)

0.4.3 (05/08/2019)
---------------------
- [Bug]: fix acme `_get_new_challenge` raising decoding error in python 3

0.4.2 (26/07/2019)
---------------------
- [Bug]: fix deployment of full certificate chain of trust on Incapsula for python3 (base64 encoding issue)

0.4.1 (25/07/2019)
---------------------
- [Bug]: Certificates deployed on Incapsula server type must contain the full chain – root CA , intermediate CA, and the origin server certificates,
  this is now default behavior for Incapsula and can be activated for any type of server.

0.4.0 (13/05/2019)
---------------------
- [Feature]: plugins now have access to file type (Certificate, private key, ...) when retrieving/saving data in storage and tacking to be able to customize behavior.

0.3.3 (06/05/2019)
---------------------
- [Bug]: fix exception raised when Incaspula site has no SSL certificate deployed yet

0.3.2 (29/04/2019)
---------------------
- [Improvement]: add email to 'Subject' section of the certificate

0.3.1 (26/04/2019)
---------------------
- [Improvement]: better error handling during certificate deployment: deploy everywhere possible and report errors in tracking record
- [Improvement]: sanitize Incapsula tests removing all Amadeus specifics
- [Improvement]: update documentation

0.3.0 (15/03/2019)
---------------------
- [Bug]: deploy from record was failing as looking first for data in storage without caching exception
- [Feature]: automatically save data in other apis when found only in a specific one
- [Feature]: support tracking in local file to more easily test different api orchestrations
- [Feature]: Support Incapsula server type
- [Feature]: ability to deploy existing certificate to outdated or new servers thanks to synchronize option
- [Feature]: support storage of credentials in local file ~/.autossl in ini format

0.2.3 (19/02/2019)
---------------------
- [Bug]: host is an optional parameter in server configuration + fix for credential enum
- [Feature]: possibility to specify only global config without certificate information for deployment to retrieve blueprint from storage/tracking

0.2.2 (14/02/2019)
-------------------
- [Bug]: fix package delivery: unable to access subpackages from external module

0.2.1 (14/02/2019)
-------------------
- [Bug]: fix package delivery (missing subfolders)
- [Feature]: add 'version' option in command line to display package information

0.2.0 (13/02/2019)
-------------------
- [Feature] make autossl generic to support any type of storage for artifacts persistency and tracking mechanism

0.1.13 (07/02/2019)
-------------------
- [Improvement]: Do not block renewal if challenge cannot be verified from local machine as validation will be performed anyway by Certificate Authority

0.1.12 (07/02/2019)
-------------------
- [Improvement]: Do not block renewal if server is not reachable from local machine

0.1.11 (19/12/2018)
-------------------
- [Improvement]: Remove prompt when renew is called with force option

0.1.10 (19/12/2018)
-------------------
- [Improvement]: Modify delivery to ensure proper artifact publication

0.1.9 (19/12/2018)
------------------
- [Improvement]: Return tracking record Id when applicable in ssl_manager.renew method

0.1.8 (10/12/2018)
------------------
- [Improvement]: support custom certificate filename for each server

0.1.7 (13/09/2018)
---------------------
- [Improvement]: allow no servers section specified in ssl blueprint to just manage certificate request without server interaction

0.1.6 (27/08/2018)
---------------------
- [Improvement]: add possibility to use any servers type. No automatic checks for now, they will always generate new certificates

0.1.5 (06/07/2018)
---------------------
- [Improvement]: add retry capability in case of connection error for all http connections

0.1.4 (06/06/2018)
---------------------
- [Improvement]: add retry capability to challenge creation/deletion in case of connection error for automated certificate renewal

0.1.3 (24/04/2018)
---------------------
- [Bug]: fix default parameters for command line

0.1.2 (24/04/2018)
---------------------
- [Bug]: add missing entry point for command line in setup.py

0.1.1 (11/04/2018)
---------------------
- [Bug]: fix config files missing in package delivery

0.1.0 (06/04/2018)
---------------------
- First delivery
