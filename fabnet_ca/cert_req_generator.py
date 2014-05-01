from M2Crypto import BIO, m2, ASN1, RSA, EVP, X509, SMIME
from M2Crypto.util import no_passphrase_callback

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

def m2_rsa(private, passphrase=None):
    """Return M2Crypto RSA's instance of key
    """
    ciph, cb = quiet_passphrase(passphrase)
    rsakeyp = RSA.load_key_string(str(private), cb)
    return rsakeyp

def m2_pkey(private, passphrase=None):
    """Return M2Crypto EVP's instance of key
    """
    rsakeyp = m2_rsa(private, passphrase)
    ciph, cb = quiet_passphrase(passphrase)
    evp_pkey = EVP.PKey(md='sha1')
    evp_pkey.assign_rsa(rsakeyp)
    return evp_pkey

def gen_request(private, CN, passphrase=None, country=None, locality=None, \
                    organization=None, OU=None, state=None, email=None):
    """Generate request with instance informations
    """
    rqst = X509.Request()
    issuer_name = rqst.get_subject()
    issuer_name.CN = str(CN)
    if country:
        issuer_name.C = country
    if locality:
        issuer_name.L = locality
    if organization:
        issuer_name.O = organization
    if OU:
        issuer_name.OU = OU
    if state:
        issuer_name.SP = state
    if email:
        issuer_name.Email = email

    issuer_pkey = m2_pkey(private, passphrase)
    rqst.set_pubkey(issuer_pkey)
    rqst.sign(pkey=issuer_pkey, md='sha1')

    return rqst.as_pem()

