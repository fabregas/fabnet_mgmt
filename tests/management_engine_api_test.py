import unittest
import time
import os
import sys
import logging
import threading
import json
import random
import base64
os.environ['FABNET_PLUGINS_CONF'] = 'tests/plugins.yaml'

from fabnet_mgmt.engine.mgmt_db import MgmtDatabaseManager
from fabnet_mgmt.engine.management_engine_api import ManagementEngineAPI
from fabnet_mgmt.engine.exceptions import *
from fabnet_mgmt.engine.constants import *
from fabnet_mgmt.engine.schedule_core import ScheduledTask
from fabnet_mgmt.engine.schedule_core import ScheduleManager

path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(path, '..'))
sys.path.append(os.path.join(path, '../fabnet_core'))
from fabnet.core.key_storage import KeyStorage, InvalidPassword

from pymongo import MongoClient

KS_PATH = './tests/ks/test.p12'
KS_PASSWD = 'node'



class TestTask(ScheduledTask):
    @classmethod
    def get_wait_time(cls):
        return 5

    def process(self):
        self.mgmt_api.update_config({'some_val': 'TTTT'})

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
            ManagementEngineAPI.initial_configuration(dbm, '', '', 'localhost')
        with self.assertRaises(MEInvalidConfigException):
            ManagementEngineAPI.initial_configuration(dbm, 'test-cluster', '', 'localhost')
        with self.assertRaises(MEInvalidConfigException):
            ManagementEngineAPI.initial_configuration(dbm, 'sh', '', 'localhost')
        with self.assertRaises(MEInvalidConfigException):
            ManagementEngineAPI.initial_configuration(dbm, 'test_cluster', KS_PATH, '')

        ManagementEngineAPI.initial_configuration(dbm, 'test_cluster', '', '')

        with self.assertRaises(MEAlreadyExistsException):
            ManagementEngineAPI.initial_configuration(dbm, 'test_cluster', '', '')
        
        #dbm.set_config(None, {DBK_CONFIG_SECURED_INST: '0'})
        mgmt_api = ManagementEngineAPI(dbm)

        with self.assertRaises(MEAuthException):
            mgmt_api.get_config(None, None)

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
            mgmt_api.get_config(session_id, None)

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

        config = mgmt_api.get_config(ma_session_id, None)
        self.assertNotEqual(config, {})
        config = {DBK_CONFIG_CLNAME: 'testcluster'}
        mgmt_api.set_config(ma_session_id, None, config)
        c_config = mgmt_api.get_config(ma_session_id, None)
        self.assertTrue(c_config.has_key(DBK_CONFIG_CLNAME))
        self.assertEqual(c_config[DBK_CONFIG_CLNAME], 'testcluster')

        key = mgmt_api.get_ssh_client().get_pubkey()
        TestManagementEngineAPI.key = key
        self.assertTrue(len(key)>0)

        #check plugins
        ret = mgmt_api.test_api_method(ma_session_id, {'test': 0})
        self.assertEqual(ret, {'test': 0})

        mgmt_api.logout(ma_session_id)
        mgmt_api.destroy()

    def test01_operations(self):
        dbm = MgmtDatabaseManager('localhost')
        mgmt_api = ManagementEngineAPI(dbm)
        key = mgmt_api.get_ssh_client().get_pubkey()
        self.assertTrue(len(key)>0)
        self.assertEqual(key, TestManagementEngineAPI.key)
        self.assertTrue(not mgmt_api.is_secured_installation())
        mgmt_api.destroy()

        cl = MongoClient('localhost')
        cl.drop_database('test_fabnet_mgmt_db')
        dbm = MgmtDatabaseManager('localhost')

        ManagementEngineAPI.initial_configuration(dbm, 'test_cluster', KS_PATH, 'mongodb://127.0.0.1/test_fabnet_ca')

        mgmt_api = ManagementEngineAPI(dbm)
        s = mgmt_api.authenticate('admin', 'admin')
        with self.assertRaises(MEMgmtKSAuthException):
            mgmt_api.get_config(s, None)
        mgmt_api.logout(s)
        mgmt_api.destroy()

        
        mgmt_api = ManagementEngineAPI(dbm)
        mgmt_api.init_key_storage(KS_PASSWD)
        key = mgmt_api.get_ssh_client().get_pubkey()
        self.assertTrue(mgmt_api.is_secured_installation())
        self.assertTrue(len(key)>0)
        self.assertNotEqual(key, TestManagementEngineAPI.key)
        mgmt_api.destroy()

    def test02_scheduler(self):
        dbm = MgmtDatabaseManager('localhost')
        ScheduleManager.add_task(TestTask)
        mgmt_api = ManagementEngineAPI(dbm)
        time.sleep(2)
        mgmt_api.destroy()

        mgmt_api = ManagementEngineAPI(dbm)
        try:
            val = mgmt_api.get_config_var('some_val')
            self.assertEqual(val, None)
            time.sleep(3.2)

            val = mgmt_api.get_config_var('some_val')
            self.assertEqual(val, 'TTTT')
        finally:
            mgmt_api.destroy()





if __name__ == '__main__':
    unittest.main()

