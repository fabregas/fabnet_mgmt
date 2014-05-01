
from openssl import Openssl
from M2Crypto import BIO, m2, ASN1, RSA, EVP, X509, SMIME
from M2Crypto.util import no_passphrase_callback
from settings import *

def quiet_passphrase(passphrase=None):
    if passphrase == None:
        ciph = None
        cb = no_passphrase_callback
    else:
        ciph = 'aes_128_cbc'
        cb = lambda a: passphrase
    return ciph, cb

def quiet_callback(*args):
        return

def generate_keys(passphrase, length=512, user=None):
    ciph, cb = quiet_passphrase(passphrase)
    keys = RSA.gen_key(length, 0x10001, callback=quiet_callback)
    bio = BIO.MemoryBuffer()
    keys.save_pub_key_bio(bio)
    public = bio.read()
    keys.save_key_bio(bio, cipher=ciph, callback=cb)
    private = bio.read()
    return public, private

def get_subject(CN, country, state, locality, organization, OU, email):
    """Return subject string for CSR and self-signed certs
    """
    subj = '/CN=%s' % CN

    if country:
        subj += '/C=%s' % country
    if state:
        subj += '/ST=%s' % state
    if locality:
        subj += '/localityName=%s' % locality
    if organization:
        subj += '/O=%s' % organization
    if OU:
        subj += '/organizationalUnitName=%s' % OU
    if email:
        subj += '/emailAddress=%s' % email
    return subj

def generate_ca(key_len, passphrase, role, days, cert_name='Root certificate'):
    public, ca_pkey = generate_keys(passphrase, key_len)
    ossl = Openssl()

    subject = get_subject(cert_name, CERT_C, CERT_ST, CERT_L, CERT_O, role, CERT_MAIL)

    pem = ossl.generate_self_signed_cert(days, subject, ca_pkey, passphrase)
    return ca_pkey, pem

def sign_request(rqst_pem, ca_private, ca_pem, ca_serial, days, passphrase=None, ca=False):
    """Sign a Request and return a Certificate instance
    """
    ossl = Openssl()

    pem = ossl.sign_csr(rqst_pem, ca_private, ca_pem, ca_serial, days, passphrase, ca)
    return pem


