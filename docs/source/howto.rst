How to use autossl module
=========================

Blueprinting
************
All SSL certificates are blueprinted with a yaml file defining:

* name of the certificate (used to identify easily the certificate)
* information of server (or list of servers) where certificate must be deployed.
* certificate details: type (DV, OV, ..), common name, san, renewal delay, ...
* storage: where artifacts generated will be stored
* tracking: what tracking mechanism will be used to track the operations performed (certificate renewal, deployment, ...)

Note that configuration linked to storage, tracking can be put either in a dedicated blueprint in order to reuse same global config for several certificates or in each certificate blueprint.

* **Certificate blueprint**

.. code-block:: yaml
   :linenos:

    ---
    name: tst.example.autossl.com

    servers:
      - type: autossl.server.local.LocalServer
        parameters:
          path: /etc/ssl/my_certificates
      - type: autossl.server.local.LocalServer
        parameters:
          path: /etc/ssl_path2/my_certificates

    certificate:
      type: DV
      certificate_authority: LetsEncrypt
      common_name: tst.example.autossl.com
      san:
        - tst1.example.autossl.com
        - tst2.example.autossl.com
        - tst3.example.autossl.com


* **Global configuration blueprint**

.. code-block:: yaml
   :linenos:

   ---

   certificate_authorities:
     - name: Sectigo
       key: Sectigo
       certificate_types: ['OV', 'DV']
       chain_of_trust:
         # intermediate certificate
         - |
           -----BEGIN CERTIFICATE-----
           MIIGGTCCBAGgAwIBAgIQE31TnKp8MamkM3AZaIR6jTANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UE
           BhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQK
           ExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNh
           dGlvbiBBdXRob3JpdHkwHhcNMTgxMTAyMDAwMDAwWhcNMzAxMjMxMjM1OTU5WjCBlTELMAkGA1UE
           BhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYG
           A1UEChMPU2VjdGlnbyBMaW1pdGVkMT0wOwYDVQQDEzRTZWN0aWdvIFJTQSBPcmdhbml6YXRpb24g
           VmFsaWRhdGlvbiBTZWN1cmUgU2VydmVyIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
           AQEAnJMCRkVKUkiS/FeN+S3qU76zLNXYqKXsW2kDwB0Q9lkz3v4HSKjojHpnSvH1jcM3ZtAykffE
           nQRgxLVK4oOLp64m1F06XvjRFnG7ir1xon3IzqJgJLBSoDpFUd54k2xiYPHkVpy3O/c8Vdjf1Xox
           fDV/ElFw4Sy+BKzL+k/hfGVqwECn2XylY4QZ4ffK76q06Fha2ZnjJt+OErK43DOyNtoUHZZYQkBu
           CyKFHFEirsTIBkVtkuZntxkj5Ng2a4XQf8dS48+wdQHgibSov4o2TqPgbOuEQc6lL0giE5dQYkUe
           CaXMn2xXcEAG2yDoG9bzk4unMp63RBUJ16/9fAEc2wIDAQABo4IBbjCCAWowHwYDVR0jBBgwFoAU
           U3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFBfZ1iUnZ/kxwklD2TA2RIxsqU/rMA4GA1Ud
           DwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
           BQcDAjAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQICMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6
           Ly9jcmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNy
           bDB2BggrBgEFBQcBAQRqMGgwPwYIKwYBBQUHMAKGM2h0dHA6Ly9jcnQudXNlcnRydXN0LmNvbS9V
           U0VSVHJ1c3RSU0FBZGRUcnVzdENBLmNydDAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRy
           dXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAThNAlsnD5m5bwOO69Bfhrgkfyb/LDCUW8nNTs3Ya
           t6tIBtbNAHwgRUNFbBZaGxNh10m6pAKkrOjOzi3JKnSj3N6uq9BoNviRrzwB93fVC8+Xq+uH5xWo
           +jBaYXEgscBDxLmPbYox6xU2JPti1Qucj+lmveZhUZeTth2HvbC1bP6mESkGYTQxMD0gJ3NR0N6F
           g9N3OSBGltqnxloWJ4Wyz04PToxcvr44APhL+XJ71PJ616IphdAEutNCLFGIUi7RPSRnR+xVzBv0
           yjTqJsHe3cQhifa6ezIejpZehEU4z4CqN2mLYBd0FUiRnG3wTqN3yhscSPr5z0noX0+FCuKPkBur
           cEya67emP7SsXaRfz+bYipaQ908mgWB2XQ8kd5GzKjGfFlqyXYwcKapInI5v03hAcNt37N3j0VcF
           cC3mSZiIBYRiBXBWdoY5TtMibx3+bfEOs2LEPMvAhblhHrrhFYBZlAyuBbuMf1a+HNJav5fyakyw
           xnB2sJCNwQs2uRHY1ihc6k/+JLcYCpsM0MF8XPtpvcyiTcaQvKZN8rG61ppnW5YCUtCC+cQKXA0o
           4D/I+pWVidWkvklsQLI+qGu41SWyxP7x09fn1txDAXYw+zuLXfdKiXyaNb78yvBXAfCNP6CHMntH
           WpdLgtJmwsQt6j8k9Kf5qLnjatkYYaA7jBU=
           -----END CERTIFICATE-----

     - name: Let's Encrypt
       key: LetsEncrypt
       type: autossl.ca_manager.acme_v2_http01.AcmeHttp01
       certificate_types: ['DV']
       acme_api:
         production: https://acme-v02.api.letsencrypt.org
         staging: https://acme-staging-v02.api.letsencrypt.org
       # specify where acme account key is located
       storage:
         type: autossl.storage.local.LocalFileStorage
         name: lets_encrypt_account_key
         parameters:
           path: /etc/ca_account_keys/
       chain_of_trust:
         # intermediate certificate
         - |
           -----BEGIN CERTIFICATE-----
           MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/MSQwIgYDVQQK
           ExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMTDkRTVCBSb290IENBIFgzMB4X
           DTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0NlowSjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxl
           dCdzIEVuY3J5cHQxIzAhBgNVBAMTGkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkq
           hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4
           S0EFq6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8SMx+yk13
           EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0Z8h/pZq4UmEUEz9l6YKH
           y9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWAa6xK8xuQSXgvopZPKiAlKQTGdMDQMc2P
           MTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQAB
           o4IBfTCCAXkwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEE
           czBxMDIGCCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNvbTA7
           BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9kc3Ryb290Y2F4My5w
           N2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAwVAYDVR0gBE0wSzAIBgZngQwBAgEw
           PwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcCARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNy
           eXB0Lm9yZzA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9P
           VENBWDNDUkwuY3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
           AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJouM2VcGfl96S8
           TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/wApIvJSwtmVi4MFU5aMqrSDE
           6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwuX4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPM
           TZ+sOPAveyxindmjkW8lGy+QsRlGPfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M
           +X+Q7UNKEkROb3N6KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
           -----END CERTIFICATE-----
         # root certificate
         - |
           -----BEGIN CERTIFICATE-----
           MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/MSQwIgYDVQQK
           ExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMTDkRTVCBSb290IENBIFgzMB4X
           DTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVowPzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1
           cmUgVHJ1c3QgQ28uMRcwFQYDVQQDEw5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQAD
           ggEPADCCAQoCggEBAN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmT
           rE4Orz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEqOLl5CjH9
           UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9bxiqKqy69cK3FCxolkHRy
           xXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40d
           utolucbY38EVAjqr2m7xPi71XAicPNaDaeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0T
           AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQ
           MA0GCSqGSIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69ikug
           dB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXrAvHRAosZy5Q6XkjE
           GB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZzR8srzJmwN0jP41ZL9c8PDHIyh8bw
           RLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubS
           fZGL+T0yjWW06XyxV3bqxbYoOb8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
           -----END CERTIFICATE-----


   organization:
     company_name: Autossl corporation
     street_address: Newbury street
     city: Boston
     state: Massachusetts
     postal_code: '02115'
     country_code: US

   storage:
     type: autossl.storage.gitscm.GitStorage
     credentials: git_credentials
     parameters:
       git_url: https://git.autossl.com/autossl/my_certs.git
     data:
       # type of data to store/retrieve in this storage
       - type: key
       - type: csr
       - type: crt

   tracking:
     type: autossl.tracking.local.LocalFileTracking
     parameters:
       log_folder: /var/log/ssl_logs
     data:
       - type: yaml
       - type: csr
       - type: crt

   credentials:
     git_credentials:
       type: UserPassword

   ...

Command line options
*********************

All commands accepts the following options

* `--config` (optional) is the global blueprint yaml file
* `--blueprint` is the certificate blueprint yaml file

Both `--config` and `--blueprint` files can also be merged in a single blueprint and in that case use only `--blueprint` option.
If same section (`tracking`, `storage`, ...) appears in both global config and certificate blueprint, global config is ignored and section from certificate blueprint will be used

Monitoring
**********

The `check` action allow to monitor certificates deployed on servers and provide status.

.. code-block:: bash

    $ autossl \
      --config global_config.yaml \
      --blueprint example.autossl.com.yaml check
    INFO:autossl:Processing blueprint example.autossl.com.yaml
    INFO:autossl.server.base:[LocalServer - AUTOSSL_MACHINE:/etc/ssl_path_1] - example.autossl.com - 2019-05-20T17:37:28 => valid (42 days remaining)
    INFO:autossl.ssl:Following domains not covered by certificate: [new.example.autossl.com]
    INFO:autossl.manager:Certificate definition changed for 'example.autossl.com' on server '[LocalServer - AUTOSSL_MACHINE:/etc/ssl_path_1]'
    INFO:autossl.server.base:[LocalServer - AUTOSSL_MACHINE:/etc/ssl_path_2] - example.autossl.com - 2019-05-20T17:37:28 => valid (42 days remaining)
    INFO:autossl.ssl:Following domains not covered by certificate: [new.example.autossl.com]
    INFO:autossl.manager:Certificate definition changed for 'example.autossl.com' on server '[LocalServer - AUTOSSL_MACHINE:/etc/ssl_path_2]'


Renewal
*******
Process to renew certificate is the same, whatever the CA used (Sectigo, Let's Encrypt, ...) or the type of certificate requested.
Renewal can be requested for 1 or several blueprints.

Depending on the type of certificate requested and the CA, automated certificate renewal may or not be possible.

For each blueprint, the flow starts with the following:

* compare blueprint with stored certificate: checking for close expiration, change of certificate content
* compare blueprint with existing certificate on the server(s): same checks than before + track servers with missing certificate
* generate a csr based on blueprint
* call tracking api and send it specified files in config (generally blueprint and CSR)
* then, when supported by specified CA, certificate is generated automatically with CA specified renewal method protocol (see details below) and also sent to tracking api

.. code-block:: bash

    $ autossl \
      --blueprint --blueprint example.autossl.com.yaml \
      renew --force\
    INFO:autossl.ssl_manager:Processing blueprint example.autossl.com.yaml
    INFO:autossl.ssl_manager:Force renewal for 'auto_example.autossl.com'
    Continue ? (y/n)y
    INFO:autossl.ssl_manager:Start renewal process for certificate 'auto_example.autossl.com'
    INFO:autossl.ssl_manager:Tracking record created: TR 98765432: SSL certificate for example.autossl.com
    INFO:autossl.ssl_manager:Processing blueprint example.autossl.com.yaml
    INFO:autossl.manager:Start renewal process for certificate 'example.autossl.com.yaml'
    INFO:autossl.acme.acme_manager:Parsing account key...
    INFO:autossl.acme.acme_manager:Registering account...
    INFO:autossl.acme.acme_manager:Already registered!
    INFO:autossl.acme.acme_manager:Starting validation for domain example.autossl.com
    INFO:autossl.server.local:Deploy challenge on LocalServer AUTOSSL_MACHINE:/etc/acme_dir
    INFO:autossl.acme.acme_manager:example.autossl.com verified!
    INFO:autossl.server.local:Cleanup challenge from LocalServer AUTOSSL_MACHINE:/etc/acme_dir
    INFO:autossl.acme.acme_manager:Signing certificate...
    INFO:autossl.acme.acme_manager:Certificate signed


Deployment
**********

To perform the deployment, several information are required:
- certificate
- private key
- ssl blueprint
- tracking record ID (optional)

All those information can be directly given in command line or can be retrieved directly from configured storage and/or tracking record.

1) from tracking record and blueprint (or global config)

At least global config is needed to identify tracking type and retrieve data from specified tracking record.
If only global config specified, full blueprint must be attached to tracking record to know where to deploy this certificate.

.. code-block:: bash

   $ autossl --config global_config.yaml deploy --tracking-record 12345678


2) with all information from command line

.. code-block:: bash

   $ autossl --config global_config.yaml deploy \
      --private-key example.autossl.com.key \
      --certificate example.autossl.com.crt \
      --tracking-record 12345678


These commands will:

* retrieve all needed artifacts (yaml blueprint, new certificate, ...) if not already given in command line
* ensure certificate is compatible with yaml blueprint, private key, CA certificate chain
* deploy key+certificate in all servers listed in yaml blueprint
* update tracking record with status of the deployment and set it as completed


.. code-block:: bash

    $ autossl --config global_config.yaml deploy \
       --tracking-record 98765432 \
       --private-key /etc/keys/example.autossl.com.key
    INFO:autossl.manager:Blueprint: example.autossl.com.yaml
    INFO:autossl.manager:Certificate: example.autossl.com.crt
    INFO:autossl.manager:PrivateKey: example.autossl.com.key
    INFO:autossl.server.base:[LocalServer - slave-ql6n8] - example.autossl.com - 2019-07-10T08:43:29 => valid (90 days remaining)
    INFO:autossl.server.local:Certificate/Key example.autossl.com updated successfully on [LocalServer - AUTOSSL_MACHINE:/etc/ssl_path_1].
    INFO:autossl.server.local:Certificate/Key example.autossl.com updated successfully on [LocalServer - AUTOSSL_MACHINE:/etc/ssl_path_2].

* global config is needed here to know how to retrieve tracking record specified
* --private-key is the path to the certificate private key (can also be retrieved automatically from configured storage or tracking record)
* --certificate is the path to the new certificate (can also be retrieved automatically from configured storage or tracking record)
* --tracking-record is the tracking record created in renewal step above

Note that using tracking record is optional, and you can directly give certificate blueprint, private key and SSL certificate in input of deploy.