import unittest
import time
import os
import sys
import logging
import threading
import json
import random
import base64
import BaseHTTPServer

from fabnet_mgmt.engine.mgmt_db import MgmtDatabaseManager
from fabnet_mgmt.engine.management_engine_api import ManagementEngineAPI
from fabnet_mgmt.engine.exceptions import *
from fabnet_mgmt.engine.constants import *
from fabnet_mgmt.rest.rest_service import *
from fabnet_mgmt.rest.client import *

path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(path, '..'))
sys.path.append(os.path.join(path, '../fabnet_core'))
from fabnet.core.key_storage import KeyStorage, InvalidPassword

from pymongo import MongoClient

KS_PATH = './tests/ks/test.p12'
KS_PASSWD = 'node'

class ServerThread(threading.Thread):
    def __init__(self, handler):
        super(ServerThread, self).__init__()
        self.handler = handler
        self.server = None

    def run(self):
        server_address = ('', 9944)
        self.server = BaseHTTPServer.HTTPServer(server_address, self.handler)
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()
        self.join()

class RestAPITest(unittest.TestCase):
    key = None
    SERVER = None

    def test00_init(self):
        cl = MongoClient('localhost')
        cl.drop_database('test_fabnet_mgmt_db')
        MgmtDatabaseManager.MGMT_DB_NAME = 'test_fabnet_mgmt_db'

        dbm = MgmtDatabaseManager('localhost')

        ManagementEngineAPI.initial_configuration(dbm, 'test_cluster', '', '')

        mgmt_api = ManagementEngineAPI(dbm)
        RESTHandler.setup_mgmt_api(mgmt_api)
        RestAPITest.SERVER = ServerThread(RESTHandler)
        RestAPITest.SERVER.start()
        time.sleep(1)

    def test01_init(self):
        with self.assertRaises(RESTException):
            RestAPI('http://127.0.0.1:9944', 'admin', '1q2w3e')
        
        api = RestAPI('http://127.0.0.1:9944', 'admin', 'admin')

        user_info = api.getUserInfo('admin')
        self.assertEqual(user_info[DBK_USERNAME], 'admin')
        self.assertEqual(user_info[DBK_ROLES], [ROLE_UM])

        api.changeUserPassword(None, 'qwerty')
        with self.assertRaises(RESTException):
            user_info = api.getUserInfo('admin')
        api = RestAPI('http://127.0.0.1:9944', 'admin', 'qwerty')
        api.createUser('megaadmin', 'qwerty', [ROLE_RO, ROLE_CF, ROLE_SS, ROLE_UPGR, ROLE_UM])
        api.changeUserPassword('megaadmin', 'qwerty')
        api.changeUserRoles('megaadmin', roles=[ROLE_RO, ROLE_CF, ROLE_UPGR, ROLE_NM])

        roles = api.getAvailableRoles()
        self.assertEqual(type(roles), dict)
        self.assertTrue(ROLE_SS in roles)

        api = RestAPI('http://127.0.0.1:9944', 'megaadmin', 'qwerty')
        with self.assertRaises(RESTException):
            api.changeUserPassword('admin', 'qwerty')

        with self.assertRaises(RESTException):
            api.createUser('rouser', 'qwerty', [ROLE_RO])

        config = api.getConfig(None)
        self.assertNotEqual(config, {})
        config = {DBK_CONFIG_CLNAME: 'testcluster'}

        api.setConfig(None, config)
        c_config = api.getConfig(None)
        self.assertTrue(c_config.has_key(DBK_CONFIG_CLNAME))
        self.assertEqual(c_config[DBK_CONFIG_CLNAME], 'testcluster')

        key = api.getSSHKey()
        self.assertTrue(len(key)>0)
        RestAPITest.key = key

    def test01_oper_with_ks(self):
        cl = MongoClient('localhost')
        cl.drop_database('test_fabnet_mgmt_db')
        MgmtDatabaseManager.MGMT_DB_NAME = 'test_fabnet_mgmt_db'
        dbm = MgmtDatabaseManager('localhost')

        ManagementEngineAPI.initial_configuration(dbm, 'test_cluster', KS_PATH, 'mongodb://127.0.0.1/test_fabnet_ca')
        mgmt_api = ManagementEngineAPI(dbm)
        RESTHandler.setup_mgmt_api(mgmt_api)
        api = RestAPI('http://127.0.0.1:9944', 'admin', 'admin')
        with self.assertRaises(RESTException):
            api.changeUserRoles('admin', roles=[ROLE_RO, ROLE_CF, ROLE_UPGR, ROLE_NM])
        api.initKeyStorage(KS_PASSWD)
        api.changeUserRoles('admin', roles=[ROLE_RO, ROLE_CF, ROLE_UPGR, ROLE_NM])
        key = api.getSSHKey()
        self.assertTrue(len(key)>0)
        self.assertNotEqual(key, RestAPITest.key)

        api.setRelease('DHT', 'file://%s/tests/data/valid_release.zip'%os.path.abspath('.'))
        rels = api.getReleases()
        self.assertTrue(len(rels)==1)
        rel = rels[0]
        self.assertEqual(rel[DBK_ID], 'DHT')
        self.assertTrue(rel[DBK_RELEASE_URL].startswith('file://'))
        self.assertEqual(rel[DBK_RELEASE_VERSION], '0.9a-2412')
        
        api.getNodesStat()

    def test99_stop(self):
        RestAPITest.SERVER.stop()


if __name__ == '__main__':
    unittest.main()

