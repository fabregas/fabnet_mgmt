import os

PKI_APP_DIR = os.path.abspath(os.path.dirname(__file__))

# base directory for pki storage (should be writable), defaults to PKI_APP_DIR/PKI
PKI_DIR =  os.path.join(PKI_APP_DIR, 'PKI')

# path to openssl executable
PKI_OPENSSL_BIN =  '/usr/bin/openssl'

PKI_OPENSSL_CONF = """
[ usr_cert ]
basicConstraints=CA:FALSE
nsComment=  "Easy-RSA Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
extendedKeyUsage=clientAuth
keyUsage=   digitalSignature

[ v3_ca ] 
basicConstraints = critical,CA:TRUE 
subjectKeyIdentifier = hash 
authorityKeyIdentifier = keyid:always

"""

# template name for openssl.conf
PKI_OPENSSL_TEMPLATE = 'pki/openssl.conf.in'

# self_signed_serial; The serial a self signed CA starts with. Set to 0 or 0x0 for a random number
PKI_SELF_SIGNED_SERIAL = 0x0

DB_NAME = os.environ.get('FABNET_CA_DB', None) or 'fabnet_ca_db'

CERT_C = 'UA'
CERT_ST = 'Kyiv'
CERT_L = 'Kyiv'
CERT_O = 'fabnet software'
CERT_MAIL = 'ca@fabnet.com'

CA_CERTS_FILE = os.path.join(os.environ.get('HOME', '/'), '.fabnet_ca_certificates')

CRM_ROLE = 'crm.fabnet.com'
