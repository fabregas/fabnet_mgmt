"""
From django-pki - Copyright (C) 2010 Daniel Kerwin <django-pki@linuxaddicted.de>
    http://github.com/dkerwin/django-pki

                - Copyright (C) 2010 Johan Charpentier <jcharpentier@bearstech.com>


This program and entire repository is free software; you can
redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software
Foundation; either version 2 of the License, or any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; If not, see <http://www.gnu.org/licenses/>.
"""
import os, re, sys
import datetime
import string, random

from settings import PKI_OPENSSL_BIN, PKI_OPENSSL_CONF, PKI_DIR, PKI_OPENSSL_TEMPLATE, PKI_SELF_SIGNED_SERIAL

from subprocess import Popen, PIPE, STDOUT
import shutil
from logging import getLogger
from tempfile import NamedTemporaryFile, TemporaryFile, mkdtemp

try:
    # available in python-2.5 and greater
    from hashlib import md5 as md5_constructor
except ImportError:
    # compatibility fallback
    from md5 import new as md5_constructor

logger = getLogger("pki")

##------------------------------------------------------------------##
## OpenSSLActions: All non config related actions
##------------------------------------------------------------------##

def in_temp_dir(func):
    """Create a temp dir and clean them on end of function
    """
    def new_func(*args, **kwargs):
        if args[0].tmpdir:
            return func(*args, **kwargs)
        tmpdir = mkdtemp()
        oldvalue = args[0].tmpdir
        args[0].tmpdir = tmpdir
        try:
            result = func(*args, **kwargs)
        finally:
            shutil.rmtree(tmpdir)
            args[0].tmpdir = oldvalue
        return result

    new_func.__name__ = func.__name__
    new_func.__doc__ = func.__doc__
    new_func.__dict__.update(func.__dict__)
    return new_func

class Openssl():
    '''Do the real openssl work - Generate keys, csr, sign'''

    def __init__(self, tmpdir=""):
        '''Class constructor'''

        ## Generate a random string as ENV variable name
        self.env_pw = "".join(random.sample(string.letters+string.digits, 10))

        #self.confname = PKI_OPENSSL_CONF
        self.tmpdir = tmpdir

    class VerifyError(Exception):
        """Openssl verify fails
        """
        pass

    def exec_rehash(directory):
        """call c_rehash on directory
        """
        proc = Popen("/usr/bin/c_rehash %s" % directory, shell=False, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
        stdout_value, stderr_value = proc.communicate()

        if proc.returncode != 0:
            #logger.error('openssl command "%s" failed with returncode %d' % (c[1], proc.returncode))
            #logger.error(stdout_value)

            raise self.VerifyError(stdout_value)
        else:
            return stdout_value

    def exec_openssl(self, command, stdin=None, env_vars=None, cwd=None):
        '''Run openssl command. PKI_OPENSSL_BIN doesn't need to be specified'''

        c = [PKI_OPENSSL_BIN]
        c.extend(command)

        # add PKI_DIR environment variable if caller did not set it
        if env_vars:
            env_vars.setdefault('PKI_DIR', PKI_DIR)
        else:
            env_vars = {'PKI_DIR': PKI_DIR}

        proc = Popen(c, shell=False, env=env_vars, stdin=PIPE, stdout=PIPE, stderr=STDOUT, cwd=cwd)
        stdout_value, stderr_value = proc.communicate(stdin)

        if proc.returncode != 0:
            #logger.error('openssl command "%s" failed with returncode %d' % (c[1], proc.returncode))
            #logger.error(stdout_value)

            raise self.VerifyError(stdout_value)
        else:
            return stdout_value

    def generate_self_signed_cert(self, days, subj, key, passphrase=None):
        """Generate a self signed root certificate
        """
        key_f = NamedTemporaryFile()
        key_f.write(key)
        key_f.seek(0)

        logger.info( 'Generating self-signed root certificate' )

        #command = ['req', '-config', self.confname, '-batch', '-sha1', '-new', '-x509', '-subj', subj, '-days', str(days), \
        command = ['req', '-batch', '-sha1', '-new', '-x509', '-subj', subj, '-days', str(days), \
                   '-extensions', 'v3_ca', '-key', key_f.name, '-set_serial', '1']

        if passphrase:
            command.append('-passin')
            command.append('stdin')

        pem = self.exec_openssl(command, stdin=passphrase)
        return pem

    def generate_der_encoded(self):
        '''Generate a DER encoded version of a given certificate'''

        logger.info( 'Generating DER encoded certificate for %s' % self.i.name )

        command = 'x509 -in %s -out %s -outform DER' % (self.crt, self.der)
        self.exec_openssl(command.split())

        return True

    def __get_config_file(self):
        cfg = NamedTemporaryFile()
        cfg.write(PKI_OPENSSL_CONF)
        cfg.seek(0)
        return cfg

    @in_temp_dir
    def sign_csr(self, csr, cakey, cacrt, serial_n, days, passphrase=None, ca_capable=False):
        """Sign the CSR with given CA
        """
        cfg = self.__get_config_file()
        logger.info( 'Signing CSR' )

        if ca_capable:
            extension = "v3_ca"
        else:
            extension = "usr_cert"
        csrfile = NamedTemporaryFile()
        csrfile.write(csr)
        csrfile.seek(0)
        cafile = NamedTemporaryFile()
        cafile.write(cacrt)
        cafile.seek(0)
        cakeyfile = NamedTemporaryFile()
        cakeyfile.write(cakey)
        cakeyfile.seek(0)
        certfile = NamedTemporaryFile()
        
        command = ['x509', '-req', '-set_serial', str(serial_n),'-extfile', cfg.name , '-sha1', '-days', str(days), '-in', csrfile.name, '-CA', cafile.name, '-CAkey', cakeyfile.name, '-passin', 'stdin', '-extensions', extension, '-out', certfile.name]
        self.exec_openssl(command, stdin=passphrase)
        pem = certfile.read()
        return pem

    def _revoke_certificate(self, ppf):
        '''Revoke a given certificate'''

        ## Check if certificate is already revoked. May have happened during a incomplete transaction
        if self.get_revoke_status_from_cert():
            logger.info( "Skipping revoke as it already happened" )
            return True

        logger.info( 'Revoking certificate %s' % self.i.name )

        command = 'ca -config %s -name %s -batch -revoke %s -passin env:%s' % (PKI_OPENSSL_CONF, self.i.parent, self.crt, self.env_pw)
        self.exec_openssl(command.split(), env_vars={ self.env_pw: str(ppf) })

    def renew_certificate(self):
        '''Renew/Reissue a given certificate'''

        logger.info( 'Renewing certificate %s' % self.i.name )

        if os.path.exists(self.csr):
            self.sign_csr()
        else:
            raise Exception( "Failed to renew certificate %s! CSR is missing!" % self.i.name )

    @in_temp_dir
    def verify_ca_chain(self, chain):
        """Verify the the CA chain
        """
        trusted_chain = [crt for crt in chain if crt.trust]
        certs = "".join([crt.pem for crt in chain ])

        for c in trusted_chain:
            filepath = os.path.join(self.tmpdir, "%s.0" % c.certhash)
            w = open(filepath, 'w')
            w.write(c.pem)
            w.close()
        command = ['verify', '-CApath', self.tmpdir, ]

        result = self.exec_openssl(command, stdin=certs)

        if result == "stdin: OK\n":
            return True
        else:
            raise self.VerifyError(result)

    def get_hash_from_cert(self, cert):
        """Use openssl to get the hash value of a given certificate
        """
        command = 'x509 -hash -noout'
        output  = self.exec_openssl(command.split(), cert)

        return output.rstrip("\n")

    def get_subject_from_cert(self, cert):
        """Get the subject form a given CA certificate
        """

        command = ["x509", "-noout", "-subject"]
        output  = self.exec_openssl(command, stdin=cert.pem)
        return output.rstrip("\n").lstrip("subject= ")

    def get_revoke_status_from_cert(self, cert, crl):
        """Is the given certificate already revoked? True=yes, False=no

        Beware : that don't check cert <-> crl signature
        """
        serial = cert.serial

        command = 'crl -text -noout'
        output  = self.exec_openssl(command.split(), stdin=crl)

        serial_re = re.compile('^\s+Serial\sNumber\:\s+(\w+)')
        lines = output.split('\n')
        serial = "%X" % serial
        serial = serial.rjust(2,"0")

        for l in lines:
            if serial_re.match(l):
                if serial_re.match(l).group(1) == serial:
                    #logger.info( "The certificate is revoked" )
                    return True

        return False

    def generate_index(self, ca, issued):
        """Generate Index
        http://www.mail-archive.com/openssl-users@openssl.org/msg45982.html

        The columns are defined as 
        #define DB_type         0 /* Status of the certificate */
        #define DB_exp_date     1 /* Expiry date */
        #define DB_rev_date     2 /* Revocation date */
        #define DB_serial       3       /* Serial No., index - unique */
        #define DB_file         4      
        #define DB_name         5       /* DN, index - unique when active and not disabled */

        DB_type is defined as
        #define DB_TYPE_REV    'R' /* Revoked */
        #define DB_TYPE_EXP    'E' /* Expired */
        #define DB_TYPE_VAL    'V' /* Valid */

        /!\ Only revoked for now ...

        """
        raise NotImplementedError()
        from M2Crypto.ASN1 import ASN1_UTCTIME
        index = ""
        for cert in issued:
            if cert.revoked:
                subject = self.get_subject_from_cert(cert)
                asn1 = ASN1_UTCTIME()
                asn1.set_datetime(cert)
                #expiry = asn1.
                # TODO : How can we output datetimes in ASN1_UTCTIME Format ???


    @in_temp_dir
    def generate_crl(self, ca, cakey, crlnumber, crlchain=[], issued=[], passphrase=None):
        """Generate CRL: When a CA is modified
        """
        certdir = os.path.join(self.tmpdir, "certs")
        os.mkdir(certdir, 0700)
        privdir = os.path.join(self.tmpdir, "private")
        os.mkdir(privdir, 0700)
        crldir = os.path.join(self.tmpdir, "crl")
        os.mkdir(crldir, 0700)

        # Issued
        for c in issued:
            filepath = os.path.join(certdir, "%s.0" % c.certhash)
            w = open(filepath, 'w')
            w.write(c.pem)
            w.close()

        # CA cert
        filepath = os.path.join(self.tmpdir, "cacert.pem")
        w = open(filepath, 'w')
        w.write(ca.pem)
        w.close()

        # CA key
        filepath = os.path.join(privdir, "cakey.pem")
        w = open(filepath, 'w')
        w.write(cakey)
        w.close()

        # Config
        cfg = self.__get_config_file()

        # Generate Index file
        open(os.path.join(self.tmpdir, "index.txt"), "w").write(ca.index)
        # Generate Serial file
        serial = "%X" % ca.ca_serial
        serial = serial.rjust(2,"0")
        open(os.path.join(self.tmpdir, "serial"), "w").write(serial)
        # Generate crlnumber file
        crlnumber = "%X" % crlnumber
        crlnumber = crlnumber.rjust(2,"0")
        open(os.path.join(self.tmpdir, "crlnumber"), "w").write(crlnumber)
        #open(os.path.join(self.tmpdir, "crlnumber"), "w").write("")

        # crl
        crlpath = os.path.join(self.tmpdir, "%s.r0" % ca.certhash)
        if ca.crl:
            w = open(crlpath, 'w')
            w.write(ca.crl)
            w.close()

        logger.info( 'CRL generation for CA %s' % ca )
        command = ["ca", "-config", cfg.name, "-gencrl", "-crldays", "1", "-passin", "stdin", "-out", crlpath]
        result = self.exec_openssl(command, stdin=passphrase, cwd=self.tmpdir)
        crlpem = open(crlpath, 'r').read()
        return crlpem


    @in_temp_dir
    def revoke_cert(self, ca, cakey, crlnumber, crl, cert, issued=[], passphrase=None):
        """Generate CRL: When a CA is modified
        """
        certdir = os.path.join(self.tmpdir, "certs")
        os.mkdir(certdir, 0700)
        privdir = os.path.join(self.tmpdir, "private")
        os.mkdir(privdir, 0700)
        crldir = os.path.join(self.tmpdir, "crl")
        os.mkdir(crldir, 0700)

        # Issued
        for c in issued:
            filepath = os.path.join(certdir, "%s.0" % c.certhash)
            if c == cert:
                torevoke = filepath
            w = open(filepath, 'w')
            w.write(c.pem)
            w.close()

        # CA cert
        filepath = os.path.join(self.tmpdir, "cacert.pem")
        w = open(filepath, 'w')
        w.write(ca.pem)
        w.close()

        # CA key
        filepath = os.path.join(privdir, "cakey.pem")
        keyfile = filepath
        w = open(filepath, 'w')
        w.write(cakey)
        w.close()

        # Config
        cfg = self.__get_config_file()

        # Generate Index file
        open(os.path.join(self.tmpdir, "index.txt"), "w").write(ca.index)
        # Generate Serial file
        serial = "%X" % ca.ca_serial
        serial = serial.rjust(2,"0")
        open(os.path.join(self.tmpdir, "serial"), "w").write(serial)
        # Generate crlnumber file
        crlnumber = "%X" % crlnumber
        crlnumber = crlnumber.rjust(2,"0")
        open(os.path.join(self.tmpdir, "crlnumber"), "w").write(crlnumber)
        #open(os.path.join(self.tmpdir, "crlnumber"), "w").write("")

        # crl
        crlpath = os.path.join(self.tmpdir, "crl.pem")
        if crl:
            w = open(crlpath, 'w')
            w.write(crl)
            w.close()

        #shutil.copytree(self.tmpdir, "/tmp/pkitest")
        command = ["ca", "-config", cfg.name, "-batch", "-revoke", torevoke, "-passin", "stdin" ]
        result = self.exec_openssl(command, stdin=passphrase, cwd=self.tmpdir)
        command = ["ca", "-config", cfg.name, "-gencrl", "-crldays", "1", "-passin", "stdin", "-out", crlpath]
        result = self.exec_openssl(command, stdin=passphrase, cwd=self.tmpdir)
        crlpem = open(crlpath, 'r').read()
        index = open(os.path.join(self.tmpdir, "index.txt"), 'r').read()
        return crlpem, index
