import os
import sys
from cert_req_signer import generate_ca, sign_request
from cert_req_generator import generate_keys, gen_request
from fabnet.utils.key_storage import KeyStorage

import settings as S

def create_ca_ks(output_file, password, role_name, root_ca_ks=None, CN=None):
    if os.path.exists(output_file):
        raise Exception('File %s is already exists'%output_file)

    if CN and len(str(CN))>64:
        raise Exception('Too long CN! Maximum length is 64 bytes')

    out_ks = KeyStorage(output_file, password)
    if not root_ca_ks:
        if os.path.exists(S.CA_CERTS_FILE):
            raise Exception('CA certificates file is found at %s. Can not create new root CA!'%S.CA_CERTS_FILE)

        print ' -> generating root CA key storage at %s ...'%output_file
        ca_private, ca_cert = generate_ca(2048, None, role_name, 100*365, CN)
        print ' -> OK'
    else:
        if not os.path.exists(S.CA_CERTS_FILE):
            raise Exception('CA certificates file does not found at %s!'%S.CA_CERTS_FILE)

        count = 1
        with open(S.CA_CERTS_FILE) as fd:
            for line in fd:
                if 'BEGIN CERTIFICATE' in line:
                    count += 1

        if count > 255:
            raise Exception('255 CA certificates are found! This is maximum value!')

        root_ca_private = root_ca_ks.private()
        root_ca_pem = root_ca_ks.cert()

        print ' -> generating key and certificate for %s role (serial=%s)'%(role_name, count)
        #generate pri key and certificate pair
        pub, ca_private = generate_keys(None, 2048)
        if not CN:
            CN = 'Base certificate for %s role'%role_name
        cl_ca_req = gen_request(ca_private, CN, None, \
                S.CERT_C, S.CERT_L, S.CERT_O, role_name, None, S.CERT_MAIL)
        ca_cert = sign_request(cl_ca_req, root_ca_private, root_ca_pem, count, 10*365, 'test', ca=True)
        print ' -> OK'

    out_ks.create(ca_private)
    out_ks.append_cert(ca_cert)

    with open(S.CA_CERTS_FILE, 'a') as fd:
        fd.write(ca_cert)
        
