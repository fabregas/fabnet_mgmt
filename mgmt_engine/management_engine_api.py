#!/usr/bin/python
"""
Copyright (C) 2013 Konstantin Andrusenko
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.

@package fabnet.mgmt.management_engine_api
@author Konstantin Andrusenko
@date July 24, 2013

This module contains the implementation of ManagementEngineAPI class
"""
import os
import re
import hashlib
import tempfile
import uuid
import base64

from mgmt_engine.constants import *
from mgmt_engine.exceptions import *
from mgmt_engine.key_storage import KeyStorage

from mgmt_engine.decorators import *
from mgmt_engine.users_mgmt import *
from mgmt_engine.nodes_mgmt import *

import paramiko

class MockFileObj:
    def __init__(self, data):
        self.__data = data

    def read(self, l=None):
        ret = self.__data[:l]
        self.__data = self.__data[len(ret):]
        return ret

    def readlines(self):
        return self.read().split('\n')

    def close(self):
        pass

class SSHClient:
    def __init__(self, pri=None, timeout=10):
        self.__timeout = timeout

        if pri:
            self.__pri = pri
        else:
            home = os.environ.get('HOME', '/root')
            path = os.path.join(home, '.ssh/id_rsa')
            if os.path.exists(path):
                self.__pri = paramiko.RSAKey.from_private_key_file(filename=path)
            else:
                self.__pri = None

    def get_pubkey(self):
        return self.__pri.get_base64()

    def __make_executor(self, cli):
        def executor(command, timeout=None):
            cli.log += '\n# %s\n'%command
            command += ' ;echo $? 1>&2'
            stdin, stdout, stderr = cli.exec_command(command, timeout=timeout, get_pty=True)
            out = stdout.read()
            try:
                ret_code = out.splitlines()[-1]
                out = out[:-len(ret_code)]
                ret_code = int(ret_code)
            except ValueError:
                raise Exception('Invalid return code. STDERR: %s'%out)

            cli.log += out
            if ret_code:
                cli.log += stderr.read()
            return ret_code
        return executor

    def __make_safe_exec(self, cli):
        def safe_exec(cmd):
            rcode = cli.execute(cmd)
            if rcode:
                raise MEOperException(cli.log+'\nERROR! Configuration failed!')
            return rcode
        return safe_exec

    def connect(self, hostname, port=22, username=None, password=None, pkey=None):
        cli = paramiko.SSHClient()
        #cli.get_host_keys().add(hostname, 'ssh-rsa', self.__pri)
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if pkey:
            pkey = paramiko.RSAKey.from_private_key(file_obj=MockFileObj(pkey))
        if not pkey:
            pkey = self.__pri
        cli.connect(hostname, port, username, password, pkey, timeout=self.__timeout)
        cli.log = ''
        cli.execute = self.__make_executor(cli)
        cli.safe_exec = self.__make_safe_exec(cli)
        return cli


class ManagementEngineAPI(object):
    @classmethod
    def initial_configuration(cls, db_mgr, cluster_name, is_secured_inst, node_git_repo, ca_addr):
        config = db_mgr.get_cluster_config()
        if config.has_key(DBK_CONFIG_CLNAME):
            raise MEAlreadyExistsException('Management engine is already configured!') 

        if not re.match('\w\w\w+$', cluster_name):
            raise MEInvalidConfigException('Cluster name is invalid!')

        cfg = {DBK_CONFIG_CLNAME: cluster_name,
                DBK_CONFIG_SECURED_INST: '1' if is_secured_inst else '0',
                DBK_CONFIG_NODE_GIT_REPO: node_git_repo,
                DBK_CONFIG_CA_ADDR: ca_addr}

        db_mgr.set_cluster_config(cfg)

    def __init__(self, db_mgr, ks=None):
        mgmt_api_method.mgmt_engine_api = self

        self._db_mgr = db_mgr
        self._admin_ks = ks
        self.__check_configuration()

        key = self.__init_ssh()
        self.__ssh_client = SSHClient(key)

    def __del__(self):
        if self._db_mgr:
            self._db_mgr.close()

    def __check_configuration(self):
        cluster_name = self.get_config_var(DBK_CONFIG_CLNAME)
        if not cluster_name:
            raise MENotConfiguredException('cluster name does not specified!')

        cluster_name = self.get_config_var(DBK_CONFIG_SECURED_INST)
        if cluster_name is None:
            raise MENotConfiguredException('installation type does not specified!')

        if self.is_secured_installation() and not self._admin_ks:
            raise MEInvalidArgException('Key storage should be specified for secured installation!')

    def get_ssh_client(self):
        return self.__ssh_client

    def get_config_var(self, var, default=None):
        config = self._db_mgr.get_cluster_config()
        return config.get(var, default)

    def update_config(self, new_config):
        self._db_mgr.set_cluster_config(new_config)

    def is_secured_installation(self):
        sec = self.get_config_var(DBK_CONFIG_SECURED_INST)
        if sec:
            sec = int(sec)
        return bool(sec)

    def __init_ssh(self):
        if not self._admin_ks:
            return None

        if not self.is_secured_installation():
            return None

        pwd = self._admin_ks.hexdigest()
        ssh_key = self.get_config_var(DBK_CONFIG_SSH_KEY)
        if not ssh_key:
            key = paramiko.RSAKey.generate(1024)
            f_hdl, f_path = tempfile.mkstemp()
            try:
                key.write_private_key_file(f_path, password=pwd)
                ssh_key = open(f_path).read()
                self.update_config({DBK_CONFIG_SSH_KEY: ssh_key})
            finally:
                os.close(f_hdl)
                os.remove(f_path)
 
        pkey = paramiko.RSAKey.from_private_key(file_obj=MockFileObj(ssh_key), password=pwd)
        return pkey

    def check_roles(self, session_id, need_roles):
        user = self._db_mgr.get_user_by_session(session_id)
        if user is None:
            raise MEAuthException('Unknown user session!')

        roles = user[DBK_ROLES] 
        for role in roles:
            if role in need_roles:
                return
        raise MEPermException('User does not have permissions for this action!')

    def get_allowed_methods(self, session_id):
        user = self._db_mgr.get_user_by_session(session_id)
        if user is None:
            raise MEAuthException('Unknown user session!')

        roles = user[DBK_ROLES] 
        methods = []
        for item, item_roles in mgmt_api_method.roles_map.items():
            if not item_roles:
                methods.append(item)
                continue

            for role in roles:
                if role in item_roles:
                    methods.append(item)
        return methods

    def authenticate(self, username, password):
        user = self._db_mgr.get_user_info(username)
        if not user:
            raise MEAuthException('User "%s" does not found'%username)

        pwd_hash = user[DBK_USER_PWD_HASH]
        if hashlib.sha1(password).hexdigest() != pwd_hash:
            raise MEAuthException('Password is invalid')

        session_id = uuid.uuid4().hex
        self._db_mgr.add_session(session_id, username)
        return session_id

    def logout(self, session_id):
        self._db_mgr.del_session(session_id)

    def __getattr__(self, attr):
        method = mgmt_api_method.methods.get(attr, None)
        if method is None:
            raise AttributeError('No "%s" found!'%attr)
        return method



