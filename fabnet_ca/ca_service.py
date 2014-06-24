#!/usr/bin/python
import os
import sys
import json
import traceback
from M2Crypto import BIO, m2, ASN1, RSA, EVP, X509, SMIME
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ConfigurationError
from cert_req_signer import sign_request, generate_ca
from datetime import datetime, timedelta
import urlparse
import threading
from fabnet.utils.key_storage import KeyStorage

DEBUG=True

from settings import DB_NAME, CRM_ROLE

STATUS_INIT = 'wait_for_user'
STATUS_ACTIVE = 'active'
STATUS_PENDING = 'pending'


DBK_CERTIFICATES = 'certificates'
DBK_CERT_ACTKEY = 'activation_key'
DBK_CERT_SERIALID = 'cert_serial_id'
DBK_CERT_PEM = 'cert_pem'
DBK_CERT_ISCA = 'is_CA'
DBK_CERT_TERM = 'cert_term'
DBK_CERT_ADDINFO = 'cert_add_info'
DBK_CERT_ROLE = 'cert_role'
DBK_CERT_STATUS = 'status'
DBK_CERT_MODDATE = 'mod_date'
DBK_CERT_CN = 'cert_cn'
DBK_CERT_REVOKE_DT = 'revoke_dt'



class InvalidCertRequest(Exception):
    pass

class InvalidRegistration(Exception):
    pass

class AlreadyGenerated(Exception):
    pass

class ActKeyExists(Exception):
    pass

class NotFound(Exception):
    pass

class AuthError(Exception):
    pass

class Index:
    __idx = 0
    __lock = threading.Lock()
    __suffix = 0
    __suffix_bits = 8

    @classmethod
    def init(cls, val, suffix):
        cls.__lock.acquire()
        try:
            cls.__suffix = suffix
            cls.__idx = val >> cls.__suffix_bits
        finally:
            cls.__lock.release()

    @classmethod
    def next(cls):
        cls.__lock.acquire()
        try:
            cls.__idx += 1
            return (cls.__idx << cls.__suffix_bits) | cls.__suffix
        finally:
            cls.__lock.release()

class IOStream:
    def __init__(self):
        self.__data = ''

    def write(self, data):
        self.__data += data

    def __str__(self):
        return self.__data



class CAService:
    def __init__(self, ca_db_connstr, ca_ks):
        self.__client = MongoClient(ca_db_connstr)

        try:
            self.__ca_db = self.__client.get_default_database()
        except ConfigurationError:
            self.__ca_db = self.__client[DB_NAME]

        self.certificates_collection = self.__ca_db[DBK_CERTIFICATES]
        self.certificates_collection.ensure_index(DBK_CERT_SERIALID, unique=True)
        self.certificates_collection.ensure_index(DBK_CERT_ACTKEY, unique=True)

        max_serial_id = self.certificates_collection.find().sort([(DBK_CERT_SERIALID, -1)]).limit(1)
        if max_serial_id.count() > 0:
            serial_id = max_serial_id.next()[DBK_CERT_SERIALID]
        else:
            serial_id = 0
        Index.init(serial_id, ca_ks.cert_obj().get_serial_number())

        self.ca_private = ca_ks.private()
        self.ca_pem = ca_ks.cert()

    def stop(self):
        self.__client.close()

    def get_ca_certs(self):
        certs = self.certificates_collection.find({DBK_CERT_ISCA: True})
        ret_list = []
        for cert in certs:
            ret_list.append(cert[DBK_CERT_PEM])
        return ret_list

    def add_new_certificate_info(self, sign_cert, signed_data, activation_key,
                                    cert_term, cert_role, cert_add_info=None):
        sign_cert = X509.load_cert_string(sign_cert)

        pubkey = sign_cert.get_pubkey()
        pubkey.reset_context()
        pubkey.verify_init()
        pubkey.verify_update(activation_key)
        if not pubkey.verify_final(signed_data):
            raise AuthError('Permission denied! Invalid signature!')

        ca_cert = X509.load_cert_string(self.ca_pem)
        if ca_cert.get_fingerprint() != sign_cert.get_fingerprint():
            if not sign_cert.verify(ca_cert.get_pubkey()):
                raise AuthError('Permission denied! Invalid certificate!') 

            cert_type = sign_cert.get_subject().OU
            if cert_type != CRM_ROLE:
                raise AuthError('Permission denied! Invalid certificate role!') 
            
        try:
            cert_term = int(cert_term)
        except ValueError:
            raise InvalidRegistration('Certificate term should be integer')

        if cert_term <= 0:
            raise InvalidRegistration('Certificate term should be > 0')

        if len(activation_key) < 5:
            raise InvalidRegistration('Activation key "%s" is too short!'%activation_key)
            
        if self.certificates_collection.find_one({DBK_CERT_ACTKEY: activation_key}):
            raise ActKeyExists('Certificate with key=%s is already exists in database!'%activation_key)

        if not cert_role or len(cert_role) > 64:
            raise InvalidRegistration('Invalid certificate role "%s"'%cert_role)

        serial_id = Index.next()
        self.certificates_collection.insert({DBK_CERT_ACTKEY: activation_key, DBK_CERT_TERM: cert_term,
                                    DBK_CERT_SERIALID: serial_id, DBK_CERT_ADDINFO: cert_add_info,
                                    DBK_CERT_ROLE: cert_role, DBK_CERT_STATUS: STATUS_INIT,
                                    DBK_CERT_MODDATE: datetime.now(), DBK_CERT_PEM: '', DBK_CERT_CN: ''})

        return ''


    def get_activation_info(self, activation_key):
        cert_info = self.certificates_collection.find_one({DBK_CERT_ACTKEY: activation_key})
        if not cert_info:
            raise NotFound('No information about activation key "%s" found!'%activation_key)

        return {'cert_term': cert_info[DBK_CERT_TERM], 
                'cert_add_info': cert_info[DBK_CERT_ADDINFO],
                'status': cert_info[DBK_CERT_STATUS],
                'serial_id': cert_info[DBK_CERT_SERIALID]}

    def get_certificate(self, cert_serial_id):
        cert = self.certificates_collection.find_one({DBK_CERT_SERIALID: cert_serial_id})
        if not cert:
            raise NotFound('No certificate found for serial="%s"'%cert_serial_id)

        return cert[DBK_CERT_PEM]

    def generate_certificate(self, activation_key, cert_req_pem):
        cert_info = self.certificates_collection.find_one({DBK_CERT_ACTKEY: activation_key})
        if not cert_info:
            raise NotFound('Certificate with key=%s does not found!'%activation_key)

        rqst = X509.load_request_string(cert_req_pem)
        issuer = rqst.get_subject()

        role = cert_info[DBK_CERT_ROLE]
        if issuer.OU != role:
            raise InvalidCertRequest('Invalid certificate request OU=%s. "%s" value expected'%(issuer.OU, role))

        if not issuer.CN:
            raise InvalidCertRequest('Invalid CN! REQ: %s'%rqst.as_text())

        issuer_cn = str(issuer.CN)
        if len(issuer_cn) == 0 or len(issuer_cn) > 64:
            raise InvalidRegistration('Invalid CN size. Maximum is 64 bytes, but %s occured!'%len(issuer_cn))

        if cert_info[DBK_CERT_STATUS] == STATUS_ACTIVE:
            if issuer_cn == cert_info[DBK_CERT_CN]:
                return cert_info[DBK_CERT_PEM]
            raise AlreadyGenerated('Certificate with activation key=%s is already processed!'%activation_key) 

        cert_with_cn = self.certificates_collection.find_one({DBK_CERT_CN: issuer_cn})
        if cert_with_cn:
            raise InvalidRegistration('Certificate with CN=%s is already exists!'%issuer_cn)

        #generating certificate
        serial_id = cert_info[DBK_CERT_SERIALID]
        cert_period = int(cert_info[DBK_CERT_TERM])
        revoke_dt = datetime.now() + timedelta(cert_period)
        cert_pem = sign_request(cert_req_pem, self.ca_private, self.ca_pem, serial_id, cert_period, 'test')

        cert_info[DBK_CERT_PEM] = cert_pem
        cert_info[DBK_CERT_MODDATE] = datetime.now()
        cert_info[DBK_CERT_REVOKE_DT] = revoke_dt
        cert_info[DBK_CERT_STATUS] = STATUS_ACTIVE
        cert_info[DBK_CERT_CN] = issuer_cn

        self.certificates_collection.update({DBK_CERT_ACTKEY: activation_key}, cert_info)
        return cert_pem

    def web_app(self, environ, start_response):
        def send_error(status, msg):
            if DEBUG:
                debug = IOStream()
                traceback.print_exc(file=debug)
            response_headers = [('Content-type','text/plain')]
            start_response(status, response_headers)
            resp = str(msg)
            if DEBUG:
                resp += '\nDEBUG: %s'%debug
            return [resp]

        try:
            body= ''
            try:
                length = int(environ.get('CONTENT_LENGTH', '0'))
            except ValueError:
                length= 0

            if length != 0:
                body = environ['wsgi.input'].read(length)

            params = dict(urlparse.parse_qs(body))

            def safe_get(key):
                ret = params.get(key, None)
                if ret is None:
                    raise Exception('%s expected!'%key)
                return ret[0]


            path = environ['PATH_INFO']
            if path.startswith('/get_certificate/'):
                cert_id = path.rstrip('/').split('/')[-1]
                resp = self.get_certificate(cert_id)
            else:
                if environ['REQUEST_METHOD'] != 'POST':
                    raise Exception('POST method expected!')

                if path == '/get_activation_info':
                    act_key = safe_get('activation_key')
                    resp = self.get_activation_info(act_key)
                    resp = json.dumps(resp)
                elif path == '/generate_certificate':
                    act_key = safe_get('activation_key')
                    cert_req_pem = safe_get('cert_req_pem')

                    resp = self.generate_certificate(act_key, cert_req_pem)
                elif path == '/add_new_certificate_info':
                    act_key = safe_get('activation_key')
                    cert = safe_get('sign_cert')
                    signed_data = safe_get('signed_data')
                    cert_term = safe_get('cert_term')
                    cert_add_info = safe_get('cert_add_info')
                    cert_role = safe_get('cert_role')

                    resp = self.add_new_certificate_info(cert, signed_data, act_key,
                            cert_term, cert_role, cert_add_info)

                else:
                    raise Exception('Unexpected path "%s"!'%path)
     
            status = '200 OK'
            response_headers = [('Content-type','text/plain')]
            start_response(status, response_headers)
            return [resp]
        except InvalidCertRequest, err:
            return send_error('501 InvalidCertRequest', err)
        except InvalidRegistration, err:
            return send_error('502 InvalidRegistration', err)
        except AlreadyGenerated, err:
            return send_error('503 AlreadyGenerated', err)
        except ActKeyExists, err:
            return send_error('504 ActKeyExists', err)
        except NotFound, err:
            return send_error('505 NotFound', err)
        except AuthError, err:
            return send_error('506 AuthError', err)
        except Exception, err:
            return send_error('500 Internal Server Error', err)



