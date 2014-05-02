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
import random
import string
from tempfile import NamedTemporaryFile

from fabnet_mgmt.engine.constants import *
from fabnet_mgmt.engine.exceptions import MEOperException, MEAlreadyExistsException, \
        MEInvalidConfigException, MENotConfiguredException, MEInvalidArgException, \
        MEAuthException, MEPermException 
from fabnet_mgmt.engine.decorators import MgmtApiMethod
from fabnet_mgmt.engine.users_mgmt import *
from fabnet_mgmt.engine.nodes_mgmt import *


from fabnet_ca.ca_service import CAService
from fabnet_ca.cert_req_generator import generate_keys, gen_request

from fabnet.core.constants import NODE_CERTIFICATE
from fabnet.core.key_storage import KeyStorage

import paramiko
from M2Crypto import RSA, BIO, EVP


class MockFileObj:
    def __init__(self, data):
        self.__data = data

    def read(self, rlen=None):
        ret = self.__data[:rlen]
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
        def executor(command, timeout=None, input_str=None):
            cli.log += '\n# %s\n' % command
            command += ' ;echo $? 1>&2'
            stdin, stdout, stderr = cli.exec_command(command, timeout=timeout, get_pty=True)
            if input_str:
                stdin.write(input_str + '\n')
                stdin.flush()
            out = stdout.read()
            try:
                ret_code = out.splitlines()[-1]
                out = out[:-len(ret_code)]
                ret_code = int(ret_code)
            except ValueError:
                raise Exception('Invalid return code. STDERR: %s'%out)

            cli.output = out
            cli.log += out
            if ret_code:
                cli.log += stderr.read()
            return ret_code
        return executor

    def __make_safe_exec(self, cli):
        def safe_exec(cmd, timeout=None, input_str=None):
            rcode = cli.execute(cmd, timeout, input_str)
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
        cli.output = ''
        cli.execute = self.__make_executor(cli)
        cli.safe_exec = self.__make_safe_exec(cli)
        return cli


class ManagementEngineAPI(object):
    @classmethod
    def initial_configuration(cls, db_mgr, cluster_name, is_secured_inst, ca_db_addr):
        config = db_mgr.get_config(None)
        if config.has_key(DBK_CONFIG_CLNAME):
            raise MEAlreadyExistsException('Management engine is already configured!') 

        if not re.match('\w\w\w+$', cluster_name):
            raise MEInvalidConfigException('Cluster name is invalid!')

        if is_secured_inst and not ca_db_addr:
            raise MEInvalidConfigException('CA database address expected for secure installation!')

        cfg = {DBK_CONFIG_CLNAME: cluster_name,
                DBK_CONFIG_SECURED_INST: '1' if is_secured_inst else '0',
                DBK_CONFIG_CA_DB: ca_db_addr}

        db_mgr.set_config(None, cfg)

    def __init__(self, db_mgr, admin_ks=None):
        MgmtApiMethod.set_mgmt_engine_api(self)

        self.__config_cache = None
        self.__db_mgr = db_mgr
        self._admin_ks = admin_ks
        self.__check_configuration()

        key = self.__init_ssh()
        self.__ssh_client = SSHClient(key)

        self.__ca_service = None
        if self.is_secured_installation():
            self.__ca_service = CAService(self.get_config_var(DBK_CONFIG_CA_DB), admin_ks)

    def __del__(self):
        if self.__db_mgr:
            self.__db_mgr.close()

    def __check_configuration(self):
        cluster_name = self.get_config_var(DBK_CONFIG_CLNAME)
        if not cluster_name:
            raise MENotConfiguredException('cluster name does not specified!')

        cluster_name = self.get_config_var(DBK_CONFIG_SECURED_INST)
        if cluster_name is None:
            raise MENotConfiguredException('installation type does not specified!')

        if self.is_secured_installation() and not self._admin_ks:
            raise MEInvalidArgException('Key storage should be specified for secured installation!')

    def db_mgr(self):
        return self.__db_mgr

    def get_ssh_client(self):
        return self.__ssh_client

    def get_config_var(self, var, default=None):
        if self.__config_cache is None:
            self.__config_cache = self.__db_mgr.get_config(None)
        return self.__config_cache.get(var, default)

    def update_config(self, new_config):
        self.__db_mgr.set_config(None, new_config)
        self.__config_cache = None

    def get_node_config(self, node_name):
        '''Node config structure:
                Node:
                    <global param>: <value>
                    ...
                    <node param>: <value>
                    ...
                Init:
                    NODE_NAME: <value>
                    NODE_TYPE: <value>
                    FABNET_NODE_HOST: <value>
                    FABNET_NODE_PORT: <value>
                    FIRST_NEIGHBOUR: <value>
        '''
        pass

    def is_secured_installation(self):
        sec = self.get_config_var(DBK_CONFIG_SECURED_INST)
        if sec:
            sec = int(sec)
        return bool(sec)

    def get_node_password(self, node_name):
        return self._admin_ks.hexdigest()

    def __init_ssh(self):
        if not self._admin_ks:
            return None

        if not self.is_secured_installation():
            return None

        pwd = self._admin_ks.hexdigest()
        ssh_key = self.get_config_var(DBK_CONFIG_SSH_KEY)
        if not ssh_key:
            key = RSA.gen_key(1024, e=65537)
            bio_mem = BIO.MemoryBuffer()

            key.save_key_bio(bio_mem, callback=lambda _: pwd)
            ssh_key = bio_mem.read_all()
            self.update_config({DBK_CONFIG_SSH_KEY: ssh_key})
 
        pkey = paramiko.RSAKey.from_private_key(file_obj=MockFileObj(ssh_key), password=pwd)
        return pkey


    def check_roles(self, session_id, need_roles):
        user = self.__db_mgr.get_user_by_session(session_id)
        if user is None:
            raise MEAuthException('Unknown user session!')

        roles = user[DBK_ROLES] 
        for role in roles:
            if role in need_roles:
                return
        raise MEPermException('User does not have permissions for this action!')

    def get_allowed_methods(self, session_id):
        user = self.__db_mgr.get_user_by_session(session_id)
        if user is None:
            raise MEAuthException('Unknown user session!')

        roles = user[DBK_ROLES] 
        methods = []
        for item, item_roles in MgmtApiMethod.iter_roles():
            if not item_roles:
                methods.append(item)
                continue

            for role in roles:
                if role in item_roles:
                    methods.append(item)
        return methods

    def authenticate(self, username, password):
        user = self.__db_mgr.get_user_info(username)
        if not user:
            raise MEAuthException('User "%s" does not found'%username)

        pwd_hash = user[DBK_USER_PWD_HASH]
        if hashlib.sha1(password).hexdigest() != pwd_hash:
            raise MEAuthException('Password is invalid')

        session_id = uuid.uuid4().hex
        self.__db_mgr.add_session(session_id, username)
        return session_id

    def logout(self, session_id):
        self.__db_mgr.del_session(session_id)

    def __getattr__(self, attr):
        method = MgmtApiMethod.get_method(attr)
        if method is None:
            raise AttributeError('No "%s" found!'%attr)
        return method

    def generate_node_key_storage(self, nodeaddr):
        if ':' in nodeaddr:
            nodeaddr = nodeaddr.split(':')[0]

        activation_key = ''.join(random.choice(string.uppercase+string.digits) for i in xrange(15))
        key = EVP.load_key_string(self._admin_ks.private())
        key.reset_context()
        key.sign_init()
        key.sign_update(activation_key)
        sign = key.sign_final()

        self.__ca_service.add_new_certificate_info(self._admin_ks.cert(), sign, activation_key, 36500, NODE_CERTIFICATE)
        pub, pri = generate_keys(None, length=1024)
        cert_req = gen_request(pri, nodeaddr, passphrase=None, OU=NODE_CERTIFICATE)
        cert = self.__ca_service.generate_certificate(activation_key, cert_req)

        password = self._admin_ks.hexdigest()
        tmp_file = NamedTemporaryFile()
        file_path = tmp_file.name
        tmp_file.close()
        out_ks = KeyStorage(file_path, password)
        out_ks.create(pri)
        out_ks.append_cert(cert)
        return file_path

    def get_ca_certificates(self):
        certs = self.__ca_service.get_ca_certs()
        certs.append(self._admin_ks.cert())
        return '\n'.join(certs)

