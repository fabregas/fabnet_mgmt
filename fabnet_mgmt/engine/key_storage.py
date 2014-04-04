
import os
import re
import subprocess
import hashlib
import tempfile

from M2Crypto import RSA, X509

class InvalidPassword(Exception):
    pass

OPENSSL_BIN = 'openssl'

def exec_openssl(command, stdin=None):
    cmd = [OPENSSL_BIN]
    cmd.extend(command)

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, \
            stdin=subprocess.PIPE)
    stdout_value, stderr_value = proc.communicate(stdin)

    out = stdout_value
    if stderr_value:
        out += '\n%s' % stderr_value
    if proc.returncode != 0:
        raise Exception('OpenSSL error: %s'%out)

    return proc.returncode, out

class TmpFile:
    def __init__(self):
        self.__fd = None
        self.__path = None
        f_descr, self.__path = tempfile.mkstemp('-nimbusfs')
        self.__fd = os.fdopen(f_descr, 'wb')

    @property
    def name(self):
        return self.__path

    def write(self, data):
        self.__fd.write(data)

    def flush(self):
        self.__fd.flush()

    def close(self):
        if self.__fd:
            self.__fd.close()
            self.__fd = None
        if self.__path:
            os.remove(self.__path)
            self.__path = None

    def __del__(self):
        self.close()

class KeyStorage:
    def __init__(self, path, password):
        self.__path = path
        self.__pwd = password
        self.__private = None
        self.__cert = None

        if os.path.exists(self.__path):
            self.load()

    def create(self, private):
        self.__private = private
        tmp_pri = TmpFile()
        tmp_pri.write(private)
        tmp_pri.flush()

        retcode, _ = exec_openssl(['pkcs12', '-export', '-inkey', tmp_pri.name, \
                '-nocerts', '-out', self.__path, '-password', 'stdin'], self.__pwd)

        tmp_pri.close()

    def load(self):
        tmp_file = TmpFile()
        try:
            retcode, out = exec_openssl(['pkcs12', '-in', self.__path, '-out', \
                    tmp_file.name, '-password', 'stdin', '-nodes'], self.__pwd)
        except Exception, err:
            raise InvalidPassword('Can not open key chain! Maybe pin-code is invalid!')
        finally:
            data = open(tmp_file.name).read()
            tmp_file.close()

        pkey_s = re.search('(-----BEGIN \w*\s*PRIVATE KEY-----(\w|\W)+-----END \w*\s*PRIVATE KEY-----)', data)
        if not pkey_s:
            raise Exception('Private key does not found in key chain!')
        self.__private = pkey_s.groups()[0]

        cert_s = re.search('(-----BEGIN \w*\s*CERTIFICATE-----(\w|\W)+-----END \w*\s*CERTIFICATE-----)', data)
        if cert_s:
            self.__cert = cert_s.groups()[0]

    def cert(self):
        return self.__cert

    def hexdigest(self):
        return hashlib.sha1(self.__private).hexdigest()

    def private(self):
        return self.__private

    def private_obj(self):
        return RSA.load_key_string(self.__private)

    def encrypt(self, data):
        key = self.private_obj()
        return key.public_encrypt(data, RSA.pkcs1_oaep_padding)

    def decrypt(self, data):
        key = self.private_obj()
        return key.private_decrypt(data, RSA.pkcs1_oaep_padding)

    def cert_obj(self):
        return X509.load_cert_string(self.__cert)

    def pubkey(self):
        pkey = self.cert_obj().get_pubkey()
        return pkey.get_rsa().as_pem()

    def append_cert(self, cert):
        if not self.__private:
            raise Exception('Private key does not specified!')

        tmp_pri = TmpFile()
        tmp_pri.write(self.__private)
        tmp_pri.flush()

        tmp_cert = TmpFile()
        tmp_cert.write(cert)
        tmp_cert.flush()

        retcode, out =  exec_openssl(['pkcs12', '-export', \
                '-inkey', tmp_pri.name, '-in', tmp_cert.name, '-out', self.__path, \
                '-password', 'stdin'], self.__pwd)

        tmp_pri.close()
        tmp_cert.close()


