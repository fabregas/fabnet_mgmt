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


class ManagementEngineAPI(object):
    def __init__(self, db_mgr):
        mgmt_api_method.mgmt_engine_api = self

        self._db_mgr = db_mgr
        self._admin_ks = None
        self.__admin_ks_path = self.__get_admin_ks_path()

    def __del__(self):
        if self.__admin_ks_path:
            os.remove(self.__admin_ks_path)
        if self._db_mgr:
            self._db_mgr.close()

    def is_initialized(self):
        if not self.__admin_ks_path:
            return True
        return self._admin_ks is not None

    def initialize(self, ks_pwd):
        if not self.__admin_ks_path:
            return
        self._admin_ks = KeyStorage(self.__admin_ks_path, ks_pwd)

    def __get_admin_ks_path(self):
        config = self._db_mgr.get_cluster_config()
        ks_content = config.get(DBK_CONFIG_KS, None)
        if not ks_content:
            return None

        f_hdl, f_path = tempfile.mkstemp('-admin-ks') 
        ks_content = base64.b64decode(ks_content)
        os.write(f_hdl, ks_content)
        os.close(f_hdl)
        return f_path

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



