import unittest
import time
import os
import sys
import logging
import signal
import json
import random
import subprocess
import signal
import socket
import httplib
import urllib
import random
import string
import threading
from datetime import datetime

base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../fabnet_core')))
CA_SERVICE_BIN = os.path.join(base_path, 'bin/ca_service')
CA_ADD_CERT_BIN = os.path.join(base_path, 'bin/ca-add-cert')
sys.path.append(base_path)

from fabnet.utils.key_storage import KeyStorage

from fabnet_ca.ca_ks_generator import create_ca_ks, add_ca_cert
import fabnet_ca.settings as settings
from fabnet_ca.cert_req_generator import gen_request, generate_keys

from M2Crypto import EVP, X509

PWD = 'qwerty123'
FILES = ('/tmp/test_root_ca.p12', '/tmp/test_node_ca.p12', \
        '/tmp/test_clients_ca.p12', '/tmp/test_crm_ca.p12', '/tmp/test_nodbc.p12')

CLIENT_PKEY = NODE_PKEY = None

class TestBaseCA(unittest.TestCase):
    def clear_files(self):
        for f_path in list(FILES):
            if os.path.exists(f_path):
                os.remove(f_path)

    def test_00_init_ca(self):
        from pymongo import Connection
        c = Connection()
        c.drop_database('utest_fabnet_ca')
        c.close()

        self.clear_files()
        dbconn = 'mongodb://localhost/utest_fabnet_ca'

        create_ca_ks(FILES[0], PWD, 'root', None, db_conn_str=dbconn)
        self.assertTrue(os.path.exists(FILES[0]))
        root_ks = KeyStorage(FILES[0], PWD)

        with self.assertRaises(Exception):
            KeyStorage('/some/file/name', PWD).load()
        with self.assertRaises(Exception):
            KeyStorage(FILES[0], 'fake')
        with self.assertRaises(Exception):
            create_ca_ks(FILES[1], PWD, 'node', root_ks, 'FirstDataCenter', db_conn_str='test_host')

        create_ca_ks(FILES[1], PWD, 'node', root_ks, 'FirstDataCenter', db_conn_str=dbconn)
        self.assertTrue(os.path.exists(FILES[1]))

        with self.assertRaises(Exception):
            create_ca_ks(FILES[1], PWD, 'node', root_ks, 'FirstDataCenter', db_conn_str=dbconn)

        node_ks = KeyStorage(FILES[1], PWD)

        create_ca_ks(FILES[2], PWD, 'client', root_ks, 'Base clients certificate', db_conn_str=dbconn)
        self.assertTrue(os.path.exists(FILES[2]))
        clients_ks = KeyStorage(FILES[2], PWD)

        create_ca_ks(FILES[3], PWD, 'crm.fabnet.com', node_ks, 'CRM', db_conn_str=dbconn)
        self.assertTrue(os.path.exists(FILES[3]))
        crm_ks = KeyStorage(FILES[3], PWD)
 
        crm_cert = crm_ks.cert_obj()
        node_cert = node_ks.cert_obj()
        self.assertEqual(crm_cert.get_serial_number(), 4)
        #FIXME VALIDATE CERTS self.assertTrue(sub_clients_cert.verify(cliens_cert))

        create_ca_ks(FILES[4], PWD, 'test', node_ks, 'Test', db_conn_str='test_host', serial_num=55)

        ks = KeyStorage(FILES[4], PWD)
        add_ca_cert(ks.cert(), dbconn)
        with self.assertRaises(Exception):
            add_ca_cert(ks.cert(), dbconn)


    def test_01_start_ca_service(self):
        env = os.environ
        env['FABNET_CA_DB'] = 'utest_fabnet_ca'
        p = subprocess.Popen(['python', CA_SERVICE_BIN, '127.0.0.1', '1888', FILES[1], PWD], env=env)

        for i in xrange(10):
            try:
                status, data = self._ca_call('/test')
                #print 'STATUS=%s'%status
                break
            except Exception, err:
                #print '### %s'%err
                pass
            time.sleep(0.5)
        else:
            raise Exception('CA service does not respond')

    @classmethod
    def _ca_call(cls, path, params={}, method='POST'):
        ca_addr = '127.0.0.1:1888'
        try:
            conn = httplib.HTTPConnection(ca_addr)
            params = urllib.urlencode(params)
            conn.request(method, path, params)
        except socket.error, err:
            raise Exception('CA service does not respond at http://%s%s\n%s'%(ca_addr, path, err))

        try:
            resp = conn.getresponse()

            data = resp.read()
        finally:
            conn.close()
        #print resp.reason
        return resp.status, data


    def test_02_gen_certificate_info(self):
        global CLIENT_PKEY, NODE_PKEY

        status, data, key = self._proc_activation('node', 365, 1000, '1')
        self.assertEqual(status, 502, data)

        status, data, key = self._proc_activation('node', 0, 1000)
        self.assertEqual(status, 502, data)

        status, data, key = self._proc_activation('node', 365, 1000, key, KeyStorage(FILES[2], PWD))
        self.assertEqual(status, 506, data)

        status, data, key = self._proc_activation('node', 365, 1000, key, sign='234234')
        self.assertEqual(status, 506, data)

        status, data, key = self._proc_activation('node', 365, 1000, key, KeyStorage(FILES[3], PWD))
        self.assertEqual(status, 200, data)

        status, data, key = self._proc_activation('node', 365, 1000, key, KeyStorage(FILES[3], PWD))
        self.assertEqual(status, 504, data)
        NODE_PKEY = key

        status, data, key = self._proc_activation('client', 100, 1000)
        self.assertEqual(status, 200, data)
        CLIENT_PKEY = key

    @classmethod
    def _proc_activation(cls, c_type, term, capacity, act_key=None, ks=None, sign=None):
        if not ks:
            ks = KeyStorage(FILES[1], PWD)

        if act_key is None:
            act_key = ''.join(random.choice(string.uppercase+string.digits) for i in xrange(15))

        if sign is None:
            key = EVP.load_key_string(ks.private())
            key.reset_context()
            key.sign_init()
            key.sign_update(act_key)
            sign = key.sign_final()

        status, data = cls._ca_call('/add_new_certificate_info', {'sign_cert': ks.cert(), 'signed_data': sign,
                'activation_key': act_key, 'cert_term': term,\
                'cert_add_info': capacity, 'cert_role': c_type})

        return status, data, act_key

    def test_03_gen_certificates(self):
        status, data = self._ca_call('/get_activation_info', {'activation': 'some_key'})
        self.assertEqual(status, 500, data)

        status, data = self._ca_call('/get_activation_info', {'activation_key': 'some_key'})
        self.assertEqual(status, 505, data)

        status, data = self._ca_call('/get_activation_info', {'activation_key': NODE_PKEY})
        self.assertEqual(status, 200, data)
        status, r_data = self._ca_call('/get_activation_info', {'activation_key': NODE_PKEY})
        self.assertEqual(status, 200, r_data)
        self.assertEqual(data, r_data)
        try:
            p_info = json.loads(data)
        except Exception, err:
            raise Exception('Invalid CA response: "%s"'%data)
        self.assertEqual(p_info['status'], 'wait_for_user')
        self.assertEqual(p_info['cert_add_info'], '1000')
        self.assertEqual(p_info['cert_term'], 365)
        self.assertEqual(p_info['serial_id'], (1 << 8)|2)

        pub, pri = generate_keys(None, length=2048)
        cert_req = gen_request(pri, 'kst', passphrase=None, organization='Kostik & Co', OU='my_custom_role')

        status, data = self._ca_call('/generate_certificate', \
                {'cert_req_pem': cert_req, 'activation_key': 'some_key'}) 
        self.assertEqual(status, 505, data)

        status, data = self._ca_call('/generate_certificate', \
                {'cert_req_pem': cert_req, 'activation_key': NODE_PKEY}) 
        self.assertEqual(status, 501, data)

        cert_req = gen_request(pri, '*'*65, passphrase=None, organization='Kostik & Co', OU='node')
        status, data = self._ca_call('/generate_certificate', \
                {'cert_req_pem': cert_req, 'activation_key': NODE_PKEY}) 
        self.assertEqual(status, 501, data)

        cert_req = gen_request(pri, '192.231.222.111', passphrase=None, organization='Kostik & Co', OU='node')
        status, data = self._ca_call('/generate_certificate', \
                {'cert_req_pem': cert_req, 'activation_key': NODE_PKEY}) 
        self.assertEqual(status, 200, data)

        cert = X509.load_cert_string(data)
        self.assertEqual(cert.get_serial_number(), p_info['serial_id'])
        self.assertEqual(cert.get_subject().CN, '192.231.222.111')
        self.assertEqual(cert.get_issuer().CN, 'FirstDataCenter')

        #gen client cert
        idx = (2 << 8)|2
        status, data = self._ca_call('/get_activation_info', {'activation_key': CLIENT_PKEY})
        p_info = json.loads(data)

        pub, pri = generate_keys(None, length=1024)
        cert_req = gen_request(pri, idx, passphrase=None, organization='Kostik & Co', OU='client')
        status, data = self._ca_call('/generate_certificate', \
                {'cert_req_pem': cert_req, 'activation_key': CLIENT_PKEY}) 
        self.assertEqual(status, 200, data)

        cert = X509.load_cert_string(data)
        self.assertEqual(cert.get_serial_number(), idx)
        self.assertEqual(cert.get_subject().CN, str(idx))
        self.assertEqual(cert.get_issuer().CN, 'FirstDataCenter')

        status, data = self._ca_call('/get_activation_info', {'activation_key': CLIENT_PKEY})
        self.assertEqual(status, 200, data)
        p_info = json.loads(data)
        self.assertEqual(p_info['status'], 'active')
        self.assertEqual(p_info['cert_add_info'], '1000')
        self.assertEqual(p_info['cert_term'], 100)
        self.assertEqual(p_info['serial_id'], idx)

        status, data = self._ca_call('/generate_certificate', \
                {'cert_req_pem': cert_req, 'activation_key': CLIENT_PKEY}) 
        self.assertEqual(status, 200, data)
        r_cert = X509.load_cert_string(data)

        self.assertEqual(r_cert.get_fingerprint(), cert.get_fingerprint())

        cert_req = gen_request(pri, 'some_man', passphrase=None, organization='Kostik & Co', OU='client')
        status, data = self._ca_call('/generate_certificate', \
                {'cert_req_pem': cert_req, 'activation_key': CLIENT_PKEY}) 
        self.assertEqual(status, 503, data)

    def test_50_load_test(self):
        print 'start load test'
        t0 = datetime.now()
        TC = 10
        C = 100
        threads = []
        for i in xrange(TC):
            threads.append(GenCertThread(C))

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        for thread in threads:
            self.assertEqual(thread.errs, [])
        

        print '%s certificates is generated in %s threads! Process time: %s'%(TC*C, TC, datetime.now()-t0)

    def test_99_finally(self):
        pid_file = '/tmp/CA_127.0.0.1_1888.pid'
        if os.path.exists(pid_file):
            pid = open(pid_file).read()
            os.kill(int(pid), signal.SIGINT)
            os.remove(pid_file)
        self.clear_files()

class GenCertThread(threading.Thread):
    def __init__(self, count):
        threading.Thread.__init__(self)
        self.count = count
        self.errs = []

    def run(self):
        pub, pri = generate_keys(None, length=1024)
        for i in xrange(self.count):
            status, data, key = TestBaseCA._proc_activation('client.some.org', 100, 1000)
            status, data = TestBaseCA._ca_call('/get_activation_info', {'activation_key': key})
            p_info = json.loads(data)
            cert_req = gen_request(pri, p_info['serial_id'], passphrase=None, organization='Kostik & Co', OU='client.some.org')
            status, data = TestBaseCA._ca_call('/generate_certificate', \
                    {'cert_req_pem': cert_req, 'activation_key': key}) 
            if status != 200:
                self.errs.append(data)

if __name__ == '__main__':
    unittest.main()

