import unittest
import time
import os
import logging
import threading
import json
import random
import base64
import socket
import sys
os.environ['FABNET_PLUGINS_CONF'] = 'tests/plugins.yaml'

from fabnet_mgmt.engine.mgmt_db import MgmtDatabaseManager
from fabnet_mgmt.engine.management_engine_api import ManagementEngineAPI, MockFileObj
from fabnet_mgmt.engine.exceptions import *
from fabnet_mgmt.engine.constants import *
from fabnet_mgmt.cli.base_cli import BaseMgmtCLIHandler

path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(path, '..'))
sys.path.append(os.path.join(path, '../fabnet_core'))
from fabnet.core.key_storage import KeyStorage, InvalidPassword

from pymongo import MongoClient
import pexpect
import paramiko

KS_PATH = os.path.join(path, './ks/test.p12')
KS_PASSWD = 'node'

PATH = path
BASIC_CMDS = ['HELP', 'EXIT', 'CHANGE-PWD']
USERSMGMT_CMDS = BASIC_CMDS + ['CHANGE-USER-ROLES', 'CREATE-USER',\
                        'REMOVE-USER', 'SHOW-ROLES', 'USER-INFO'] 

PROMT = 'mgmt-cli>'

class MockedSFTP:
    __files = {}

    @classmethod
    def get_files(cls):
        p = cls.__files
        cls.__files = {}
        return p

    def put(self, source, dest):
        self.__files[source] = dest

    def close(self):
        pass

class MockedExecutor:
    def __init__(self):
        self.log = ''

    def close(self):
        pass

    def open_sftp(self):
        return MockedSFTP()
    
class MockedSSHClient:
    COMMANDS_MAP = {'grep MemTotal /proc/meminfo': (0, 'MemTotal:        7725544 kB\n'),
                    'grep "model name" /proc/cpuinfo': (0, '''model name      : Intel(R) Core(TM) i7-3537U CPU @ 2.00GHz
                    model name      : Intel(R) Core(TM) i7-3537U CPU @ 2.00GHz
                    model name      : Intel(R) Core(TM) i7-3537U CPU @ 2.00GHz
                    model name      : Intel(R) Core(TM) i7-3537U CPU @ 2.00GHz\n''')}

    CONNECT_LOG = []
    COMMANDS_LOG = []
    INPUT_LOG = []

    @classmethod
    def clear_logs(cls):
        cls.CONNECT_LOG = []
        cls.COMMANDS_LOG = []
        cls.INPUT_LOG = []

    def __init__(self, pri=None, timeout=10):
        pass

    def get_pubkey(self):
        return 'AAAAB3NzaC1yc2EAAAADAQABAAABAQCdVmnvGPuCgXSnnb01wJoIg79+ObUck0Gwssda3Ff+mMuvXcwkXHZYuUB8g68STwrsM5eOIncDwGpbKmJI4bFRct8mZ6yyyFnPxm0p6KVjIAxXydp7eElBKfM3Xxaro6Lj1+IAXuRTWJx/NYGa3kHtalNUuveLvCx+WMifv42hE6u1Tgok1kkzEqXt4hQmgc/aG7g3I8zkFtzgzqdwafedfmuJ7ltGDJVf5JoEGFlw+e1hhjSFjHV+nXf6nGobcXP0blVGZUL7aOegnbATFPQ//DqnnGlBEvUCxIZkmQQtgN8qj71IqbCr+JYUnGByHTdaT2gQz8Lif8Iy9RXZqahr'

    def __make_executor(self, cli):
        def executor(command, timeout=None, input_str=None):
            if input_str:
                self.INPUT_LOG.append(input_str)
            self.COMMANDS_LOG.append(command)
            cli.log += '\n# %s\n'%command
            if command in self.COMMANDS_MAP:
                retcode, out = self.COMMANDS_MAP[command]
            else:
                retcode = 0
                out = 'ok\n'
            cli.output = out
            cli.log += out
            return retcode
        return executor

    def __make_safe_exec(self, cli):
        def safe_exec(cmd, timeout=None, input_str=None):
            rcode = cli.execute(cmd, timeout, input_str)
            if rcode:
                raise MEOperException(cli.log+'\nERROR! Configuration failed!')

            return rcode
        return safe_exec

    def connect(self, hostname, port=22, username=None, password=None, pkey=None):
        cli = MockedExecutor()
        if pkey:
            pkey = paramiko.RSAKey.from_private_key(file_obj=MockFileObj(pkey))

        self.CONNECT_LOG.append((hostname, port, username, password, pkey))
        cli.execute = self.__make_executor(cli)
        cli.safe_exec = self.__make_safe_exec(cli)
        return cli




import SocketServer
class TelnetServer(SocketServer.TCPServer):
    allow_reuse_address = True
    timeout = 2

    def handle_error(self, request, client_address):
        """Handle an error gracefully.
        """
        import sys
        tp, _,_ = sys.exc_info()
        if tp.__name__ == 'EOFException':
            return
        print '-'*40
        print 'Exception',
        print client_address
        import traceback
        traceback.print_exc()
        print '-'*40

class CLIThread(threading.Thread):
    def __init__(self, port):
        self.port = port
        self.server = None
        threading.Thread.__init__(self)
        self.setName('CLIThread')

    def run(self):
        self.server = TelnetServer(("127.0.0.1", self.port), BaseMgmtCLIHandler)
        self.server.serve_forever()

    def wait_ran(self, seconds):
        for i in xrange(seconds):
            cli = pexpect.spawn('telnet 127.0.0.1 %s'%self.port)
            try:
                cli.expect('Username:', 1)
                break
            except:
                continue
            finally:
                cli.close()
                
    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.join()

class TestMgmtCLI(unittest.TestCase):
    thread = None
    CLI = None
    CLUSTER_NAME = 'test_node'
    NODES = []
    IS_SECURED = False

    def test00_init(self):
        MockedSSHClient.clear_logs()
        with self.assertRaises(MEDatabaseException):
            dbm = MgmtDatabaseManager('some-host-name')

        cl = MongoClient('localhost')
        cl.drop_database('test_fabnet_mgmt_db')
        cl.drop_database('test_fabnet_ca')
        MgmtDatabaseManager.MGMT_DB_NAME = 'test_fabnet_mgmt_db'

        dbm = MgmtDatabaseManager('localhost')
        ManagementEngineAPI.initial_configuration(dbm, self.CLUSTER_NAME, KS_PATH if self.IS_SECURED else None,\
                'mongodb://127.0.0.1/test_fabnet_ca')

        mgmt_api = ManagementEngineAPI(dbm)

        BaseMgmtCLIHandler.mgmtManagementAPI = mgmt_api

        m_ssh_cl = MockedSSHClient()
        mgmt_api.get_ssh_client = lambda: m_ssh_cl
        TestMgmtCLI.thread = CLIThread(8022)
        TestMgmtCLI.thread.start()
        TestMgmtCLI.thread.wait_ran(2)

    def test99_stop(self):
        if TestMgmtCLI.thread:
            TestMgmtCLI.thread.stop()
        BaseMgmtCLIHandler.mgmtManagementAPI.destroy()


    def _cmd(self, cmd, in_l=None, not_in_l=None, expect=PROMT):
        if in_l:
            if type(in_l) not in [list, tuple]:
                in_expr_list = [in_l]
            else:
                in_expr_list = in_l
        else:
            in_expr_list = []

        if not_in_l:
            if type(not_in_l) not in [list, tuple]:
                not_in_expr_list = [not_in_l]
            else:
                not_in_expr_list = not_in_l
        else:
            not_in_expr_list = []

        cli =  TestMgmtCLI.CLI
        cli.sendline(cmd)
        cli.expect(expect)
        for val in in_expr_list:
            self.assertTrue(val in cli.before, 'Expr "%s" not in "%s"'%(val, cli.before))
        for val in not_in_expr_list:
            self.assertTrue(val not in cli.before, 'Expr "%s" in "%s"'%(val, cli.before))
        return cli.before


    def test01_create_mgmt_user(self):
        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('admin')
            cli.expect('Password:')
            cli.sendline('admin')
            if self.IS_SECURED:
                cli.expect('key storage password:')
                cli.sendline(KS_PASSWD)
            cli.expect(PROMT)

            cli.sendline('create-user nodes-admin readonly nodesmanage configure startstop')
            cli.expect('password:')
            cli.sendline('test')
            cli.expect('password:')
            cli.sendline('test')
            cli.expect(PROMT)
        finally:
            cli.sendline('exit')
            cli.expect(pexpect.EOF)
            cli.close(force=True)

        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('nodes-admin')
            cli.expect('Password:')
            cli.sendline('test')
            cli.expect(PROMT)

            TestMgmtCLI.CLI = cli

            self._cmd('help show-releases', ['sh-releases'])
            self._cmd('show-releases', [], ['Error', 'error'])

            self._cmd('help set-release', ['software release'])
            self._cmd('set-release', 'Usage: SET-RELEASE <node type> <release url>')
            self._cmd('set-release test-node-type', 'Usage: SET-RELEASE <node type> <release url>')
            self._cmd('set-release test-node-type test', 'Bad release URL')
            self._cmd('set-release test-node-type file://%s/data/invalid_release'%PATH, 'File is not a zip file')
            self._cmd('set-release test-node-type file://%s/data/novers_release.zip'%PATH, 'installed')
            self._cmd('set-release DHT file://%s/data/valid_release.zip'%PATH, 'installed')
            self._cmd('set-release MGMT file://%s/data/valid_release.zip'%PATH, 'installed')

            self._cmd('show-releases', ['unknown', '0.9a-2412'], ['Error', 'error'])
        finally:
            cli.sendline('exit')
            cli.expect(pexpect.EOF)
            cli.close(force=True)
            TestMgmtCLI.CLI = None


    def test06_nodesmgmt_installnodes(self):
        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('nodes-admin')
            cli.expect('Password:')
            cli.sendline('test')
            cli.expect(PROMT)

            TestMgmtCLI.CLI = cli
            MockedSFTP.get_files()
            MockedSSHClient.clear_logs()

            self._cmd('i-pnode test_hostname.com:322 test_user file:/%s/ks/key.pem'%PATH, 'configured!')

            for i, (node_type, node_name) in enumerate(self.NODES):
                self._cmd('install-node test_hostname.com %s externa_addr_test_node:222%s'% \
                        (node_type,i), 'installed')
            self._cmd('shnodes', [i[1] for i in self.NODES])
        finally:
            cli.sendline('exit')
            cli.expect(pexpect.EOF)
            cli.close(force=True)
            TestMgmtCLI.CLI = None


    def test09_nodesmgmt_remove_nodes(self):
        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('nodes-admin')
            cli.expect('Password:')
            cli.sendline('test')
            cli.expect(PROMT)

            TestMgmtCLI.CLI = cli
            
            for i, (node_type, node_name) in enumerate(self.NODES):
                self._cmd('rm-node %s --force'%node_name, 'removed')
            self._cmd('rm-pnode test_hostname.com --force', 'removed')

            self._cmd('help')
        finally:
            cli.sendline('exit')
            cli.expect(pexpect.EOF)
            cli.close(force=True)
            TestMgmtCLI.CLI = None







class TestMgmtCLIBase(TestMgmtCLI):
    def test02_incorrect_auth(self):
        def check(username, pwd):
            cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
            cli.logfile_read = sys.stdout
            try:
                cli.expect('Username:')
                cli.sendline(username)
                cli.expect('Password:')
                cli.sendline(pwd)
                cli.expect('ERROR!')
                cli.expect(pexpect.EOF)
            finally:
                cli.close(force=True)
        check('testuser', 'testpwd')
        check('admin', 'testpwd')
        check('testuser', 'admin')

    def test02_usersmgmt(self):
        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('admin')
            cli.expect('Password:')
            cli.sendline('admin')
            cli.expect(PROMT)

            TestMgmtCLI.CLI = cli

            self._cmd('help', USERSMGMT_CMDS) 
            self._cmd('')
            self._cmd('some-cmd', 'Unknown command')

            self.show_roles_test(cli)
            self.create_user_test(cli)
            self.user_info_test(cli)
            self.change_user_roles(cli)
            self.change_pwd_test(cli)

            cli.sendline('exit')
            cli.expect(pexpect.EOF)
        finally:
            cli.close(force=True)
            TestMgmtCLI.CLI = None

    def show_roles_test(self, cli):
        self._cmd('help show-roles', ['shroles', 'shr'])
        self._cmd('shr', ROLES_DESC.keys())

    def create_user_test(self, cli):
        self._cmd('help create-user', ['createuser', 'cru'])
        self._cmd('create-user', 'Usage: CREATE-USER <user name> <role1> [<role2> ...]')

        cli.sendline('create-user newuser testrole')
        cli.expect('password:')
        cli.sendline('test')
        cli.expect('password:')
        cli.sendline('test1')
        cli.expect(PROMT)
        self.assertTrue('Error: ' in cli.before)
    
        cli.sendline('create-user newuser testrole')
        cli.expect('password:')
        cli.sendline('test')
        cli.expect('password:')
        cli.sendline('test')
        cli.expect(PROMT)
        self.assertTrue('Error! [60]' in cli.before)

        cli.sendline('create-user newuser readonly usersmanage')
        cli.expect('password:')
        cli.sendline('test')
        cli.expect('password:')
        cli.sendline('test')
        cli.expect(PROMT)
        self.assertTrue('Error!' not in cli.before)
        self.assertTrue('ser "newuser" is created!' in cli.before)

    def user_info_test(self, cli):
        self._cmd('help user-info', 'userinfo')
        self._cmd('user-info', 'Usage: USER-INFO <user name>')
        self._cmd('user-info someuser', 'Error! No user')
        self._cmd('user-info admin', ['admin', 'usersmanage'])
        self._cmd('user-info newuser', ['newuser', 'readonly', 'usersmanage', 'No sessions'])

    def change_user_roles(self, cli):
        self._cmd('help CHANGE-USER-ROLES', 'chur')
        self._cmd('change-user-roles', 'Usage: CHANGE-USER-ROLES <user name> <role1> ')
        self._cmd('change-user-roles someuser readonly', 'Error! [50]')
        self._cmd('change-user-roles newuser readonlyE', 'Error! [60]')
        self._cmd('change-user-roles newuser readonly', 'installed')

        self._cmd('user-info newuser', ['newuser', 'readonly'], ['usersmanage'])

    def change_pwd_test(self, cli):
        self._cmd('help change-pwd')

        cli.sendline('change-pwd')
        cli.expect('password:')
        cli.sendline('test123')
        cli.expect('password:')
        cli.sendline('test123')
        cli.expect(PROMT)
        self.assertTrue('Error!' not in cli.before)
        self.assertTrue('Password is changed' in cli.before)

        cli.sendline('change-pwd test')
        cli.expect('password:')
        cli.sendline('test123')
        cli.expect('password:')
        cli.sendline('test123')
        cli.expect(PROMT)
        self.assertTrue('Error! [50]' in cli.before)

        cli.sendline('change-pwd newuser')
        cli.expect('password:')
        cli.sendline('test123')
        cli.expect('password:')
        cli.sendline('test')
        cli.expect(PROMT)
        self.assertTrue('Error: password verification' in cli.before)

        cli.sendline('change-pwd newuser')
        cli.expect('password:')
        cli.sendline('test')
        cli.expect('password:')
        cli.sendline('test')
        cli.expect(PROMT)
        self.assertTrue('Error!' not in cli.before)
        self.assertTrue('Password is changed' in cli.before)

    def test03_usersmgmt_relogin(self):
        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('admin')
            cli.expect('Password:')
            cli.sendline('admin')
            cli.expect('ERROR!')
            cli.expect(pexpect.EOF)
        finally:
            cli.close(force=True)

        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('newuser')
            cli.expect('Password:')
            cli.sendline('test')
            cli.expect(PROMT)

            TestMgmtCLI.CLI = cli

            self._cmd('help', BASIC_CMDS) 

            cli.sendline('change-pwd')
            cli.expect('password:')
            cli.sendline('qwerty123')
            cli.expect('password:')
            cli.sendline('qwerty123')
            cli.expect(PROMT)
            self.assertTrue('Error!' not in cli.before)
            self.assertTrue('Password is changed' in cli.before)
        finally:
            cli.sendline('exit')
            cli.expect(pexpect.EOF)
            cli.close(force=True)
            TestMgmtCLI.CLI = None

    def test04_usersmgmt_removeuser(self):
        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('admin')
            cli.expect('Password:')
            cli.sendline('test123')
            cli.expect(PROMT)

            TestMgmtCLI.CLI = cli
            self._cmd('help remove-user', 'rmuser') 
            self._cmd('remove-user', 'Usage: REMOVE-USER <user name>') 
            self._cmd('remove-user someuser', 'Error! [50]')
            self._cmd('remove-user newuser', 'removed')
        finally:
            cli.sendline('exit')
            cli.expect(pexpect.EOF)
            cli.close(force=True)
            TestMgmtCLI.CLI = None

        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('newuser')
            cli.expect('Password:')
            cli.sendline('test')
            cli.expect('ERROR!')
        finally:
            cli.expect(pexpect.EOF)
            cli.close(force=True)


    def test06_nodesmgmt_installnodes(self):
        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('nodes-admin')
            cli.expect('Password:')
            cli.sendline('test')
            cli.expect(PROMT)

            TestMgmtCLI.CLI = cli
            MockedSFTP.get_files()
            MockedSSHClient.clear_logs()
            self._cmd('help install-physical-node', 'i-pnode') 
            self._cmd('install-physical-node', 'Usage: INSTALL-PHYSICAL-NODE <node hostname>[:<ssh port>] <ssh user name> --pwd | <ssh key url>') 

            self._cmd('i-pnode test_hostname.com:322 test_user /test/file', 'Error! [60] Unsupported URL type!')
            self._cmd('i-pnode test_hostname.com:322 test_user file:/test/file', 'Error! [50] Local file "test/file" does not found!')
            self._cmd('i-pnode test_hostname.com:322 test_user file:/%s/cli_test.py'%PATH, 'Unexpected error: not a valid RSA private key file')
            self.assertEqual(len(MockedSSHClient.CONNECT_LOG), 0, MockedSSHClient.CONNECT_LOG)

            dbm = MgmtDatabaseManager('localhost')
            node = dbm.get_physical_node('test_hostname.com')
            self.assertEqual(node, None)

            self._cmd('i-pnode test_hostname.com:322 test_user file:/%s/ks/key.pem'%PATH, 'configured!')
            self.assertEqual(len(MockedSSHClient.CONNECT_LOG), 2, MockedSSHClient.CONNECT_LOG)
            self.assertEqual(MockedSSHClient.CONNECT_LOG[1], ('test_hostname.com', 322, 'fabnet', None, None))
            self.assertEqual(MockedSSHClient.CONNECT_LOG[0][:4], ('test_hostname.com', 322, 'test_user', None))
            self.assertTrue(MockedSSHClient.CONNECT_LOG[0][4] is not None)
            self.assertEqual(len(MockedSSHClient.COMMANDS_LOG), 11)#, MockedSSHClient.COMMANDS_LOG)
            MockedSSHClient.clear_logs()
            
            node = dbm.get_physical_node('test_hostname.com')
            self.assertNotEqual(node, None)

            cli.sendline('i-pnode test_hostname.com:322 test_user --pwd')
            cli.expect('Password:')
            cli.sendline('testpassword')
            cli.expect('Error! \[55\]')
            cli.expect(PROMT)

            self._cmd('help show-ssh-key', 'sh-sshkey')
            self._cmd('show-ssh-key', 'ssh-rsa')

            self._cmd('help install-node', 'i-node')
            self._cmd('install-node', 'Usage: INSTALL-NODE')
            self._cmd('install-node some-host dht externa_addr_test_node', \
                    'Error! [50] Physical node "some-host" does not installed')
            self._cmd('install-node test_hostname.com unkn-type externa_addr_test_node:2222', \
                    'Error! [50] Node type "UNKN-TYPE" does not configured in the system!')
            self._cmd('install-node test_hostname.com dht externa_addr_test_node:2222 test-#@node', \
                    'Error! [20] Invalid node name')
            self._cmd('install-node test_hostname.com dht externa_addr_test_node:2222', \
                    'installed')
            self.assertEqual(len(MockedSSHClient.CONNECT_LOG), 1, MockedSSHClient.CONNECT_LOG)
            self.assertEqual(len(MockedSSHClient.COMMANDS_LOG), 3 if self.IS_SECURED else 2, MockedSSHClient.COMMANDS_LOG)

            files = MockedSFTP.get_files()
            if self.IS_SECURED:
                self.assertEqual(len(files), 2)

                cl = MongoClient('localhost')
                ca_db = cl['test_fabnet_ca']
                cert = ca_db['certificates'].find_one({'cert_cn': 'externa_addr_test_node'})
                self.assertTrue(cert is not None)
                self.assertTrue(len(cert['cert_pem']) > 0)
                self.assertTrue(cert['cert_serial_id'] > 0)
                self.assertEqual(cert['status'], 'active')
            else:
                self.assertEqual(len(files), 1, files)

            self._cmd('install-node test_hostname.com mgmt mgmt_test_node:2223', 'installed')
        finally:
            cli.sendline('exit')
            cli.expect(pexpect.EOF)
            cli.close(force=True)
            TestMgmtCLI.CLI = None


    def test07_nodesmgmt_show_nodes(self):
        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('nodes-admin')
            cli.expect('Password:')
            cli.sendline('test')
            cli.expect(PROMT)

            TestMgmtCLI.CLI = cli

            self._cmd('help show-nodes', ['shownodes', 'shnodes'])
            self._cmd('show-nodes -err', 'Error! [60]')
            self._cmd('show-nodes -p', ['test_hostname.com', 'HOSTNAME', ' 4 '])

            self._cmd('shnodes', ['test_node01'])

            test_stat = { "NeighboursInfo" : 
                { "uppers_balance" : -1, "superiors_balance" : -1 },
              "OperationsProcessorProcStat" :
                { "threads" : 2, "memory" : 19089.44 },
              "FriAgentWMStat" :
                { "workers" : 5, "busy" : 0 },
              "SystemInfo" :
                { "loadavg_10" : "0.43", "loadavg_5" : "0.21", "uptime" : "0:03:23.001197", "loadavg_15" : "0.48", "fabnet_version" : "unknown" },
              "OperatorWorkerWMStat" : 
                { "workers" : 5, "busy" : 1 },
              "FriServerProcStat" :
                { "threads" : 6, "memory" : 19276.4 },
              "OperationsProcessorWMStat" :
                { "workers" : 5, "busy" : 0 },
              "OperatorProcStat" :
                { "threads" : 14, "memory" : 21156 },
              "OperationsProcTime" :
                { "GetNodeConfig" : 0, "TopologyCognition" : 0.0032046666666666664, "NotifyOperation" : 0, "UpgradeNode" : 0, 
                    "ManageNeighbour" : 0, "UpdateNodeConfig" : 0, "NodeStatistic" : 0.0038022, "DiscoveryOperation" : 0 },
            }
            MgmtDatabaseManager.MGMT_DB_NAME = 'test_fabnet_mgmt_db'
            dbm = MgmtDatabaseManager('localhost')
            dbm.update_node_stat('externa_addr_test_node:2222', test_stat)

            self._cmd('help fabnet-stat', ['fabnetstat', 'fstat'])
            self._cmd('fabnet-stat', ['test_node01', 'MEMORY', 'VERSION', 'unknown', \
                                        '5/0', '5/1', '0.21/0.43/0.48', '-1/-1'])

            self._cmd('help operations-stat', ['opstat', 'ostat'])
            self._cmd('opstat', ['Operation', 'Process time', \
                                'TopologyCognition', '3.2', '3.8'])
        finally:
            cli.sendline('exit')
            cli.expect(pexpect.EOF)
            cli.close(force=True)
            TestMgmtCLI.CLI = None

    def test08_nodesmgmt_conf_startstop(self):
        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('nodes-admin')
            cli.expect('Password:')
            cli.sendline('test')
            cli.expect(PROMT)

            TestMgmtCLI.CLI = cli

            self._cmd('set-config', 'Usage: SET-CONFIG')
            self._cmd('help set-config', 'set-conf')
            self._cmd('set-config GL_TEST_PARAM \'Test string value\'', 'updated in database')
            self._cmd('set-config ND_TEST_PARAM 34523523.34 fake_node', 'Error! [50] Node "fake_node" does not found!')
            self._cmd('set-config ND_TEST_PARAM 34523523.34 test_node01', 'updated in database')
            self._cmd('set-config GL_TEST_PARAM \'specific value for node\' test_node01', 'updated in database')

            self._cmd('help show-config', 'sh-conf')
            self._cmd('sh-conf', ['Test string value', 'GL_TEST_PARAM', 'cluster_name'], ['ND_TEST_PARAM', '__ssh_key']) 
            self._cmd('show-config fakenode', 'Error! [50] Node "fakenode" does not found!') 
            self._cmd('sh-conf test_node01', ['specific value for node', 'GL_TEST_PARAM', 'ND_TEST_PARAM', '34523523.34'],\
                                                ['Test string value', 'cluster_name']) 
            self._cmd('sh-conf test_node01 full', 'Invalid argument')
            self._cmd('sh-conf test_node01 --full', ['specific value for node', 'GL_TEST_PARAM', 'ND_TEST_PARAM', '34523523.34',\
                                                'cluster_name']) 


            self.assertEqual(len(MockedSSHClient.INPUT_LOG), 0)

            self._cmd('start-nodes', 'Usage: START-NODES')
            self._cmd('help start-nodes', 'startnodes')
            self._cmd('start-nodes unkn-node', 'Error! [50] Node "unkn-node" does not found!')
            self._cmd('start-nodes test_node01', ['Starting', 'Done'])
            self._cmd('start-nodes test_node[00-02]', ['Node "test_node02" does not found!'])
            self._cmd('start-nodes test_node[00-01]', ['Starting', 'Done'], ['Error'])

            self.assertEqual(len(MockedSSHClient.INPUT_LOG), 3 if self.IS_SECURED else 0)

            self._cmd('reload-nodes test_node[00-01]', ['Rebooting', 'Done', 'Skipped'], ['Error'])
            
            self._cmd('stop-nodes', 'Usage: STOP-NODES')
            self._cmd('help stop-nodes', 'stopnodes')
            self._cmd('stop-nodes unkn-node', 'Error! [50] Node "unkn-node" does not found!')
            self._cmd('stop-nodes test_node01', ['Stopping', 'Done'])

            MockedSSHClient.clear_logs()
            self._cmd('help software-upgrade', 'softup')
            dbm = MgmtDatabaseManager('localhost')
            dbm.change_node_status('mgmt_test_node:2223', 1)
            self._cmd('software-upgrade', 'Unable to call UpgradeNode operation')

            BaseMgmtCLIHandler.mgmtManagementAPI.fri_call_net = lambda naddr, mname, p: (0, 'ok')
            self._cmd('software-upgrade', 'upgrade process is started')

            self.plugins_test(cli)
        finally:
            cli.sendline('exit')
            cli.expect(pexpect.EOF)
            cli.close(force=True)
            TestMgmtCLI.CLI = None

    def plugins_test(self, cli):
        #test plugins
        self._cmd('help test-plugin-operation', 'testplugins')
        self._cmd('test-plugin-operation \'some message\'', 'RESPONSE: some message')

    def test09_nodesmgmt_remove_nodes(self):
        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('nodes-admin')
            cli.expect('Password:')
            cli.sendline('test')
            cli.expect(PROMT)

            TestMgmtCLI.CLI = cli

            self._cmd('remove-physical-node', 'Usage: REMOVE-PHYSICAL-NODE <node hostname>')
            self._cmd('help remove-physical-node', 'rm-pnode')
            self._cmd('remove-physical-node some-unknown-node --force', 'Error! [50]')
            self._cmd('remove-physical-node test_hostname.com --invalid', 'Error! [60] Invalid argument')

            cli.sendline('rm-pnode test_hostname.com')
            cli.expect('Are you sure')
            cli.sendline('n')
            cli.expect(PROMT)

            cli.sendline('rm-pnode test_hostname.com')
            cli.expect('Are you sure')
            cli.sendline('Y')
            cli.readline()
            cli.expect('Error! \[20\] Physical node')
            cli.expect(PROMT)


            self._cmd('remove-node', 'Usage: REMOVE-NODE <node name>')
            self._cmd('help remove-node', 'rm-node')
            self._cmd('remove-node some-unknown-node --force', 'Error! [50]')
            self._cmd('remove-node test_node01 --invalid', 'Error! [60] Invalid argument')
            cli.sendline('rm-node test_node01')
            cli.expect('Are you sure')
            cli.sendline('n')
            cli.expect(PROMT)

            cli.sendline('rm-node test_node00')
            cli.expect('Are you sure')
            cli.sendline('Y')
            cli.readline()
            cli.expect('removed')
            cli.expect(PROMT)


            self._cmd('rm-node test_node01 --force', 'removed')
            self._cmd('rm-pnode test_hostname.com --force', 'removed')

            self._cmd('help')
        finally:
            cli.sendline('exit')
            cli.expect(pexpect.EOF)
            cli.close(force=True)
            TestMgmtCLI.CLI = None


class SecuredTestMgmtCLI(TestMgmtCLIBase):
    IS_SECURED = True

if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestMgmtCLIBase))
    suite.addTest(unittest.makeSuite(SecuredTestMgmtCLI))
    runner = unittest.TextTestRunner()
    ret = runner.run(suite)
    sys.exit(len(ret.failures))
