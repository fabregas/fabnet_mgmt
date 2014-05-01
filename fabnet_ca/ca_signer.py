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

from roles import *
from settings import DB_NAME

STATUS_ACTIVE = 'active'
STATUS_PENDING = 'pending'


class InvalidCertRequest(Exception):
    pass

class InvalidRegistration(Exception):
    pass

class AlreadyGenerated(Exception):
    pass

class PaymentExists(Exception):
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

        self.certificates_collection = self.__ca_db['certificates']
        self.certificates_collection.ensure_index('cert_serial_id', unique=True)
        self.payments_collection = self.__ca_db['payments']
        self.payments_collection.ensure_index('payment_key', unique=True)

        max_serial_id = self.certificates_collection.find().sort([("cert_serial_id", -1)]).limit(1)
        if max_serial_id.count() > 0:
            serial_id = max_serial_id.next()['cert_serial_id']
        else:
            serial_id = 0
        Index.init(serial_id, ca_ks.cert_obj().get_serial_number())

        self.ca_private = ca_ks.private()
        self.ca_pem = ca_ks.cert()

    def stop(self):
        self.__client.close()

    def get_ca_certs(self):
        certs = self.certificates_collection.find({'ca': True})
        ret_list = []
        for cert in certs:
            ret_list.append(cert['cert_pem'])
        return ret_list

    def process_payment(self, cert, signed_data, pay_key, service_term, service_capacity, service_endpoint):
        cert = X509.load_cert_string(cert)

        pubkey = cert.get_pubkey()
        pubkey.reset_context()
        pubkey.verify_init()
        pubkey.verify_update(pay_key)
        if not pubkey.verify_final(signed_data):
            raise AuthError('Permission denied! Invalid signature!')

        ca_cert = X509.load_cert_string(self.ca_pem)
        if ca_cert.get_fingerprint() != cert.get_fingerprint():
            if not cert.verify(ca_cert.get_pubkey()):
                raise AuthError('Permission denied! Invalid certificate!') 

            cert_type = cert.get_subject().OU
            if cert_type != CRM_ROLE:
                raise AuthError('Permission denied! Invalid certificate role!') 
            
        try:
            service_term = int(service_term)
        except ValueError:
            raise InvalidRegistration('Service term should be integer')

        try:
            service_capacity = int(service_capacity)
        except ValueError:
            raise InvalidRegistration('Service capacity should be integer')

        if service_term <= 0:
            raise InvalidRegistration('Service term should be > 0')

        if service_capacity < 0:
            raise InvalidRegistration('Service capacity should be >= 0')

        if len(pay_key) < 5:
            raise InvalidRegistration('Key "%s" is too short!'%service_endpoint)
            
        if self.payments_collection.find_one({'payment_key': pay_key}):
            raise PaymentExists('Payment with key=%s is already exists in database!'%pay_key)

        if service_endpoint not in ROLES_MAP:
            raise InvalidRegistration('Invalid service endpoint "%s"'%service_endpoint)

        self.payments_collection.insert({'payment_key': pay_key, 'service_term': service_term,
                                    'cert_id': None, 'service_capacity': service_capacity,
                                    'service_endpoint': service_endpoint,
                                    'status': 'WAIT_FOR_USER', 'payment_dt': datetime.now()})

        return ''


    def get_payment_info(self, pay_key, client_cn=None):
        payment = self.payments_collection.find_one({'payment_key': pay_key})
        if not payment:
            raise NotFound('Payment with key=%s does not found!'%pay_key)

        if not payment['cert_id']: 
            if client_cn and len(str(client_cn)) > 64:
                raise InvalidRegistration('Invalid CN size. Maximum is 64 bytes, but %s occured!'%len(str(client_cn)))

            serial_id = Index.next()
            if not client_cn:
                client_cn = serial_id

            self.certificates_collection.insert({'cert_cn': client_cn, 'cert_type': payment['service_endpoint'], \
                    'cert_serial_id': serial_id, 'status': STATUS_PENDING, 'cert_pem': '',\
                    'register_dt': None, 'revoke_dt': None}, safe=True)
            payment['cert_id'] = serial_id
            self.payments_collection.update({'payment_key':payment['payment_key']}, payment)
        else:
            cert = self.certificates_collection.find_one({'cert_serial_id': payment['cert_id']})
            client_cn = cert['cert_cn']
        
        return json.dumps({'service_term': payment['service_term'], 
                            'service_capacity': payment['service_capacity'],
                            'status': payment['status'],
                            'serial_id': payment['cert_id'],
                            'cert_cn': client_cn})


    def validate_client_cn(self, client_cn, role=CLIENT_ROLE):
        cert = self.certificates_collection.find_one({'cert_cn': client_cn})
        if not cert:
            return
            #raise InvalidRegistration('Client with CN=%s does not registered!'%client_cn)

        if cert['cert_type'] != role:
            raise InvalidRegistration('Invalid certificate type!')

        if cert['status'] != STATUS_ACTIVE:
            raise InvalidRegistration('Client account does not active!')

        #if cert['cert_pem']:
        #    raise AlreadyGenerated('Client certificate is already generated!')

    def generate_client_cert(self, client_cn, payment, cert, cert_req_pem, role=CLIENT_ROLE):
        ca_private = self.ca_private
        ca_pem = self.ca_pem

        serial_id = payment['cert_id']
        cert_period = int(payment['service_term'])
        revoke_dt = datetime.now() + timedelta(cert_period)
        cert_pem = sign_request(cert_req_pem, ca_private, ca_pem, serial_id, cert_period, 'test')

        cert['cert_pem'] = cert_pem
        cert['register_dt'] = datetime.now()
        cert['revoke_dt'] = revoke_dt
        cert['status'] = STATUS_ACTIVE
        self.certificates_collection.update({'cert_serial_id': serial_id}, cert)        

        payment['status'] = 'PROCESSED'
        self.payments_collection.update({'payment_key':payment['payment_key']}, payment)
        return cert_pem

    def get_certificate(self, cert_serial_id):
        cert = self.certificates_collection.find_one({'cert_serial_id': cert_serial_id})
        if not cert:
            raise NotFound('No certificate found for serial="%s"'%cert_serial_id)

        return cert['cert_pem']

    def generate_and_sign(self, payment, cert_req_pem, role=CLIENT_ROLE):
        rqst = X509.load_request_string(cert_req_pem)
        issuer = rqst.get_subject()

        ou = issuer.OU
        if ou != role:
            raise InvalidCertRequest('Invalid certificate request OU. "%s" value expected'%role)

        serial_id = payment['cert_id']
        cert = self.certificates_collection.find_one({'cert_serial_id': serial_id})
        if not cert:
            raise NotFound('No certificate found for serial="%s"'%serial_id)
        if str(cert['cert_cn']) != issuer.CN:
            raise InvalidRegistration('Certificate CN=%s is invalid!'%issuer.CN)

        if payment['status'] == 'PROCESSED':
            return cert['cert_pem']

        if payment['status'] != 'WAIT_FOR_USER':
            raise AlreadyGenerated('Payment with key=%s is already processed!'%pay_key) 

        cert = self.generate_client_cert(issuer.CN, payment, cert, cert_req_pem, role)
        return cert

    def generate_certificate(self, pay_key, cert_req_pem):
        payment = self.payments_collection.find_one({'payment_key': pay_key})
        if not payment:
            raise NotFound('Payment with key=%s does not found!'%pay_key)

        role = ROLES_MAP.get(payment['service_endpoint'], None)
        if role is None:
            raise InvalidRegistration('Invalid payment type "%s"'%payment['service_endpoint'])

        return self.generate_and_sign(payment, cert_req_pem, role)


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

                if path == '/get_payment_info':
                    pay_key = safe_get('payment_key')
                    cert_cn = params.get('cert_cn', None)
                    if cert_cn:
                        cert_cn = cert_cn[0]
                    resp = self.get_payment_info(pay_key, cert_cn)
                elif path == '/generate_certificate':
                    pay_key = safe_get('payment_key')
                    cert_req_pem = safe_get('cert_req_pem')

                    resp = self.generate_certificate(pay_key, cert_req_pem)
                elif path == '/process_payment':
                    pay_key = safe_get('payment_key')
                    cert = safe_get('certificate')
                    signed_data = safe_get('signed_data')
                    service_term = safe_get('service_term')
                    service_capacity = safe_get('service_capacity')
                    service_endpoint = safe_get('service_endpoint')

                    resp = self.process_payment(cert, signed_data, pay_key, service_term,\
                            service_capacity, service_endpoint)

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
        except PaymentExists, err:
            return send_error('504 PaymentExists', err)
        except NotFound, err:
            return send_error('505 NotFound', err)
        except AuthError, err:
            return send_error('506 AuthError', err)
        except Exception, err:
            return send_error('500 Internal Server Error', err)



