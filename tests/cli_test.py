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

from mgmt_engine.mgmt_db import MgmtDatabaseManager
from mgmt_engine.management_engine_api import ManagementEngineAPI, MockFileObj
from mgmt_engine.exceptions import *
from mgmt_engine.constants import *
from mgmt_engine.key_storage import KeyStorage, InvalidPassword
from mgmt_cli.base_cli import BaseMgmtCLIHandler

from pymongo import MongoClient
import pexpect
import paramiko

KS_PATH = './tests/ks/test.p12'
KS_PASSWD = 'node'

BASIC_CMDS = ['HELP', 'EXIT', 'CHANGE-PWD']
USERSMGMT_CMDS = BASIC_CMDS + ['CHANGE-USER-ROLES', 'CREATE-USER',\
                        'REMOVE-USER', 'SHOW-ROLES', 'USER-INFO'] 

PROMT = 'mgmt-cli>'

class MockedExecutor:
    def __init__(self):
        self.log = ''

    def close(self):
        pass

class MockedSSHClient:
    COMMANDS_MAP = {'grep MemTotal /proc/meminfo': (0, 'MemTotal:        7725544 kB\n'),
                    'grep "model name" /proc/cpuinfo': (0, '''model name      : Intel(R) Core(TM) i7-3537U CPU @ 2.00GHz
                    model name      : Intel(R) Core(TM) i7-3537U CPU @ 2.00GHz
                    model name      : Intel(R) Core(TM) i7-3537U CPU @ 2.00GHz
                    model name      : Intel(R) Core(TM) i7-3537U CPU @ 2.00GHz\n''')}

    CONNECT_LOG = []
    COMMANDS_LOG = []

    @classmethod
    def clear_logs(cls):
        cls.CONNECT_LOG = []
        cls.COMMANDS_LOG = []

    def __init__(self, pri=None, timeout=10):
        pass

    def get_pubkey(self):
        return 'thisismockedfakepublickey'

    def __make_executor(self, cli):
        def executor(command, timeout=None):
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
        def safe_exec(cmd):
            rcode = cli.execute(cmd)
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
            self.join()

class TestMgmtCLI(unittest.TestCase):
    thread = None
    CLI = None

    def test00_init(self):
        with self.assertRaises(MEDatabaseException):
            dbm = MgmtDatabaseManager('some-host-name')

        cl = MongoClient('localhost')
        cl.drop_database('test_fabnet_mgmt_db')
        MgmtDatabaseManager.MGMT_DB_NAME = 'test_fabnet_mgmt_db'

        dbm = MgmtDatabaseManager('localhost')
        ManagementEngineAPI.initial_configuration(dbm, 'test_cluster', True, 'git@test.com', '')
        mgmt_api = ManagementEngineAPI(dbm, ks=KeyStorage(KS_PATH, KS_PASSWD))

        BaseMgmtCLIHandler.mgmtManagementAPI = mgmt_api

        m_ssh_cl = MockedSSHClient()
        mgmt_api.get_ssh_client = lambda: m_ssh_cl
        TestMgmtCLI.thread = CLIThread(8022)
        TestMgmtCLI.thread.start()
        TestMgmtCLI.thread.wait_ran(2)

    def test99_stop(self):
        if TestMgmtCLI.thread:
            TestMgmtCLI.thread.stop()

    def test01_incorrect_auth(self):
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

    def test05_nodesmgmt_installphnode(self):
        cli = pexpect.spawn('telnet 127.0.0.1 8022', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('admin')
            cli.expect('Password:')
            cli.sendline('test123')
            cli.expect(PROMT)

            cli.sendline('create-user nodes-admin readonly nodesmanage')
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
            self._cmd('help install-physical-node', 'i-pnode') 
            self._cmd('install-physical-node', 'Usage: INSTALL-PHYSICAL-NODE <node hostname>[:<ssh port>] <ssh user name> --pwd | <ssh key url>') 

            self._cmd('i-pnode test_hostname.com:322 test_user /test/file', 'Error! [60] Unsupported URL type!')
            self._cmd('i-pnode test_hostname.com:322 test_user file:/test/file', 'Error! [50] Local file "test/file" does not found!')
            self._cmd('i-pnode test_hostname.com:322 test_user file:/./tests/cli_test.py', 'Unexpected error: not a valid RSA private key file')
            self.assertEqual(len(MockedSSHClient.CONNECT_LOG), 0, MockedSSHClient.CONNECT_LOG)

            dbm = MgmtDatabaseManager('localhost')
            node = dbm.get_physical_node('test_hostname.com')
            self.assertEqual(node, None)

            self._cmd('i-pnode test_hostname.com:322 test_user file:/./tests/ks/key.pem', 'configured!')
            self.assertEqual(len(MockedSSHClient.CONNECT_LOG), 2, MockedSSHClient.CONNECT_LOG)
            self.assertEqual(MockedSSHClient.CONNECT_LOG[1], ('test_hostname.com', 322, 'fabnet', None, None))
            self.assertEqual(MockedSSHClient.CONNECT_LOG[0][:4], ('test_hostname.com', 322, 'test_user', None))
            self.assertTrue(MockedSSHClient.CONNECT_LOG[0][4] is not None)
            self.assertEqual(len(MockedSSHClient.COMMANDS_LOG), 10)#, MockedSSHClient.COMMANDS_LOG)
            MockedSSHClient.clear_logs()
            
            node = dbm.get_physical_node('test_hostname.com')
            self.assertNotEqual(node, None)

            cli.sendline('i-pnode test_hostname.com:322 test_user --pwd')
            cli.expect('Password:')
            cli.sendline('testpassword')
            cli.expect('Error! \[55\]')
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
            self._cmd('show-nodes -p', ['test_hostname.com', 'HOSTNAME', ' 4 '])
        finally:
            cli.sendline('exit')
            cli.expect(pexpect.EOF)
            cli.close(force=True)
            TestMgmtCLI.CLI = None

if __name__ == '__main__':
    unittest.main()

