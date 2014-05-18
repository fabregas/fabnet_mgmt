import os
import sys
from cert_req_signer import generate_ca, sign_request
from cert_req_generator import generate_keys, gen_request
from fabnet.utils.key_storage import KeyStorage
from ca_service import *


import settings as S

class CADatabase:
    def __init__(self, ca_db_connstr):
        try:
            self.__client = MongoClient(ca_db_connstr)
            try:
                self.__ca_db = self.__client.get_default_database()
            except ConfigurationError:
                self.__ca_db = self.__client[S.DB_NAME]
        except Exception, err:
            self.__connected = False
            print ('Warning! Unable to connect to CA database: %s'%err)
            return
        self.__connected = True
        self.certificates_collection = self.__ca_db[DBK_CERTIFICATES]
        self.certificates_collection.ensure_index(DBK_CERT_SERIALID, unique=True)
        self.certificates_collection.ensure_index(DBK_CERT_ACTKEY, unique=True)

    def close(self):
        self.__client.close()

    def connected(self):
        return self.__connected

    def get_void_serial_num(self):
        certs = self.certificates_collection.find({DBK_CERT_ISCA: True}).sort([(DBK_CERT_SERIALID, 1)])
        serial_num = 0
        for i in xrange(certs.count()):
            serial_num = i+1
            if serial_num < int(certs[i][DBK_CERT_SERIALID]):
                return serial_num
        return serial_num + 1

    def add_ca_cert(self, serial_num, role, cn, cert):
        self.certificates_collection.insert({DBK_CERT_SERIALID: serial_num, DBK_CERT_ISCA: True,
                DBK_CERT_ROLE: role, DBK_CERT_STATUS: STATUS_ACTIVE, DBK_CERT_ACTKEY: 'CA_%s'%serial_num,
                                    DBK_CERT_MODDATE: datetime.now(), DBK_CERT_PEM: cert, DBK_CERT_CN: cn})

def add_ca_cert(cert, db_conn_str):
    ca_db = CADatabase(db_conn_str)
    if not ca_db.connected():
        raise Exception('No connection to CA database')

    cert_o = X509.load_cert_string(cert)
    cert_name = cert_o.get_subject().CN
    role = cert_o.get_subject().OU
    serial_num = cert_o.get_serial_number()

    ca_db.add_ca_cert(serial_num, role, cert_name, cert)
    ca_db.close()


def create_ca_ks(output_file, password, role_name, root_ca_ks=None, CN=None, \
                serial_num=None, db_conn_str='localhost'):
    if os.path.exists(output_file):
        raise Exception('File %s is already exists'%output_file)

    if CN and len(str(CN))>64:
        raise Exception('Too long CN! Maximum length is 64 bytes')

    ca_db = CADatabase(db_conn_str)

    out_ks = KeyStorage(output_file, password)
    if not root_ca_ks:
        serial_num = 1
        if not CN:
            CN = 'root'
        print ' -> generating root CA key storage at %s ...'%output_file
        ca_private, ca_cert = generate_ca(2048, None, role_name, 10*365, CN)
        print ' -> OK'
    else:
        if not serial_num:
            if not ca_db.connected():
                raise Exception('No connection for CA database! '\
                        'Specify valid database connect string or certificate serial number')
            serial_num = ca_db.get_void_serial_num()

        if serial_num > 255:
            raise Exception('255 CA certificates are found! This is maximum value!')

        root_ca_private = root_ca_ks.private()
        root_ca_pem = root_ca_ks.cert()

        print ' -> generating key and certificate for %s role (serial=%s)'%(role_name, serial_num)
        #generate pri key and certificate pair
        pub, ca_private = generate_keys(None, 2048)
        if not CN:
            CN = 'Base certificate for %s role'%role_name
        cl_ca_req = gen_request(ca_private, CN, None, \
                S.CERT_C, S.CERT_L, S.CERT_O, role_name, None, S.CERT_MAIL)
        ca_cert = sign_request(cl_ca_req, root_ca_private, root_ca_pem, serial_num, 10*365, 'test', ca=True)
        print ' -> OK'

    out_ks.create(ca_private)
    out_ks.append_cert(ca_cert)

    if ca_db.connected():
        ca_db.add_ca_cert(serial_num, role_name, CN, ca_cert)
        ca_db.close()
    else:
        print 'Notice! Certificate does not saved into CA database.\n'\
                'Use ca-add-cert utility for adding CA certificates into CA database'
        
