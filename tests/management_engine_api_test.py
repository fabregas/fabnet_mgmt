import unittest
import time
import os
import logging
import threading
import json
import random
import base64

from mgmt_engine.mgmt_db import MgmtDatabaseManager
from mgmt_engine.management_engine_api import ManagementEngineAPI
from mgmt_engine.exceptions import *
from mgmt_engine.constants import *
from mgmt_engine.key_storage import KeyStorage, InvalidPassword

from pymongo import MongoClient

KS_PATH = './tests/ks/test.p12'
KS_PASSWD = 'node'

class TestManagementEngineAPI(unittest.TestCase):
    key = None
    def test00_init(self):
        with self.assertRaises(MEDatabaseException):
            dbm = MgmtDatabaseManager('some-host-name')

        cl = MongoClient('localhost')
        cl.drop_database('test_fabnet_mgmt_db')
        MgmtDatabaseManager.MGMT_DB_NAME = 'test_fabnet_mgmt_db'

        dbm = MgmtDatabaseManager('localhost')
        with self.assertRaises(MENotConfiguredException):
            mgmt_api = ManagementEngineAPI(dbm)

        with self.assertRaises(MEInvalidConfigException):
            ManagementEngineAPI.initial_configuration(dbm, '', True, 'git@test.com', '')
        with self.assertRaises(MEInvalidConfigException):
            ManagementEngineAPI.initial_configuration(dbm, 'test-cluster', True, 'git@test.com', '')
        with self.assertRaises(MEInvalidConfigException):
            ManagementEngineAPI.initial_configuration(dbm, 'sh', True, 'git@test.com', '')

        ManagementEngineAPI.initial_configuration(dbm, 'test_cluster', True, 'git@test.com', '')
        with self.assertRaises(MEInvalidArgException):
            mgmt_api = ManagementEngineAPI(dbm)

        with self.assertRaises(MEAlreadyExistsException):
            ManagementEngineAPI.initial_configuration(dbm, 'test_cluster', False, 'git@test.com', '')

        dbm.set_cluster_config({DBK_CONFIG_SECURED_INST: '0'})
        mgmt_api = ManagementEngineAPI(dbm)

        with self.assertRaises(MEAuthException):
            mgmt_api.get_cluster_config(None)

        with self.assertRaises(MEAuthException):
            mgmt_api.authenticate('test', 'test')
        with self.assertRaises(MEAuthException):
            mgmt_api.authenticate('admin', 'test')

        session_id = mgmt_api.authenticate('admin', 'admin')
        
        methods = mgmt_api.get_allowed_methods(session_id)
        self.assertTrue('create_user' in methods)

        user_info = mgmt_api.get_user_info(session_id, 'admin')
        self.assertEqual(user_info[DBK_USERNAME], 'admin')
        self.assertEqual(user_info[DBK_ROLES], [ROLE_UM])

        mgmt_api.change_user_password(session_id, None, 'qwerty')
        mgmt_api.create_user(session_id, 'megaadmin', 'qwerty', \
                [ROLE_RO, ROLE_CF, ROLE_SS, ROLE_UPGR, ROLE_UM])
        mgmt_api.change_user_password(session_id, 'megaadmin', 'qwerty')

        mgmt_api.change_user_roles(session_id, 'megaadmin', [ROLE_RO, ROLE_CF, ROLE_UPGR])

        mgmt_api.logout(session_id)
        with self.assertRaises(MEAuthException):
            mgmt_api.get_cluster_config(session_id)

        with self.assertRaises(MEAuthException):
            mgmt_api.authenticate('admin', 'admin')

        session_id = mgmt_api.authenticate('admin', 'qwerty')

        roles = mgmt_api.get_available_roles(session_id)
        self.assertEqual(type(roles), dict)
        self.assertTrue(ROLE_SS in roles)

        ma_session_id = mgmt_api.authenticate('megaadmin', 'qwerty')

        with self.assertRaises(MEPermException):
            mgmt_api.change_user_password(ma_session_id, 'admin', 'qwerty')

        with self.assertRaises(MEPermException):
            mgmt_api.create_user(ma_session_id, 'rouser', 'qwerty', [ROLE_RO])

        with self.assertRaises(MEInvalidArgException):
            mgmt_api.create_user(session_id, 'rouser', 'qwerty', ['ooops'])
        mgmt_api.create_user(session_id, 'rouser', 'qwerty', [ROLE_RO])
        with self.assertRaises(MEAlreadyExistsException):
            mgmt_api.create_user(session_id, 'rouser', 'qwerty', [ROLE_RO])

        with self.assertRaises(MENotFoundException):
            mgmt_api.change_user_roles(session_id, 'someuser', [ROLE_RO, ROLE_SS])

        with self.assertRaises(MEInvalidArgException):
            mgmt_api.create_user(session_id, 'test', 'dd', ROLE_RO)

        with self.assertRaises(MEInvalidArgException):
            mgmt_api.create_user(session_id, '', 'dd', [ROLE_RO])

        with self.assertRaises(MEInvalidArgException):
            mgmt_api.change_user_roles(session_id, 'rouser', ROLE_RO)
        
        mgmt_api.remove_user(session_id, 'rouser')
        with self.assertRaises(MEAuthException):
            mgmt_api.authenticate('rouser', 'qwerty')
        mgmt_api.logout(session_id)

        config = mgmt_api.get_cluster_config(ma_session_id)
        self.assertNotEqual(config, {})
        config = {DBK_CONFIG_CLNAME: 'testcluster'}
        mgmt_api.configure_cluster(ma_session_id, config)
        c_config = mgmt_api.get_cluster_config(ma_session_id)
        self.assertTrue(c_config.has_key(DBK_CONFIG_CLNAME))
        self.assertEqual(c_config[DBK_CONFIG_CLNAME], 'testcluster')

        key = mgmt_api.get_ssh_client().get_pubkey()
        TestManagementEngineAPI.key = key
        self.assertTrue(len(key)>0)

        mgmt_api.logout(ma_session_id)

    def test01_operations(self):
        dbm = MgmtDatabaseManager('localhost')
        mgmt_api = ManagementEngineAPI(dbm, ks=KeyStorage(KS_PATH, KS_PASSWD))
        key = mgmt_api.get_ssh_client().get_pubkey()
        self.assertTrue(len(key)>0)
        self.assertEqual(key, TestManagementEngineAPI.key)
        self.assertTrue(not mgmt_api.is_secured_installation())

        config = {DBK_CONFIG_SECURED_INST: '1'}
        mgmt_api.update_config(config)
        
        mgmt_api = ManagementEngineAPI(dbm, ks=KeyStorage(KS_PATH, KS_PASSWD))
        key = mgmt_api.get_ssh_client().get_pubkey()
        self.assertTrue(mgmt_api.is_secured_installation())
        self.assertTrue(len(key)>0)
        self.assertNotEqual(key, TestManagementEngineAPI.key)



if __name__ == '__main__':
    unittest.main()

