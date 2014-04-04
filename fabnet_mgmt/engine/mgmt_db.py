#!/usr/bin/python
"""
Copyright (C) 2013 Konstantin Andrusenko
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.

@package fabnet.mgmt.mgmt_db
@author Konstantin Andrusenko
@date July 24, 2013

This module contains the implementation of MgmtDatabaseManager class
"""

import hashlib
from datetime import datetime

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ConfigurationError

from fabnet_mgmt.engine.exceptions import MEDatabaseException, MEInvalidArgException, \
                        MEAlreadyExistsException, MENotFoundException 
from fabnet_mgmt.engine.constants import *

class MgmtDatabaseManager:
    MGMT_DB_NAME = 'fabnet_mgmt_db'

    def __init__(self, conn_str):
        try:
            self.__client = MongoClient(conn_str)
        except ConnectionFailure, err:
            raise MEDatabaseException('No database connection! Details: %s'%err)

        try:
            self.__mgmt_db = self.__client.get_default_database()
        except ConfigurationError:
            self.__mgmt_db = self.__client[self.MGMT_DB_NAME]

        self.__check_users()

    def __check_users(self):
        users_cnt = self.__mgmt_db[DBK_USERS].find({}).count()
        if users_cnt:
            return
        self.create_user('admin', hashlib.sha1('admin').hexdigest(), [ROLE_UM])

    def close(self):
        self.__client.close()

    def get_user_info(self, username):
        user = self.__mgmt_db[DBK_USERS].find_one({DBK_USERNAME: username})
        return user

    def __validate(self, value, c_type, minlen=None, val_name=None, possible_vals=None):
        if not val_name:
            val_name = value

        if not isinstance(value, c_type):
            raise MEInvalidArgException('"%s" should be an instance of %s (%s occured)'\
                    %(val_name, c_type, type(value)))

        if minlen and len(value) < minlen:
            raise MEInvalidArgException('len(%s) < %s raised'%(val_name, minlen))

        if possible_vals:
            if type(value) not in (list, tuple):
                value = [value]
            for item in value:
                if item not in possible_vals:
                    raise MEInvalidArgException('"%s" does not supported! Possible values: %s'\
                            %(item, ', '.join(possible_vals)))

    def create_user(self, username, pwd_hash, roles):
        user = self.get_user_info(username)
        if user:
            raise MEAlreadyExistsException('User "%s" is already exists'%username)

        self.__validate(username, str, minlen=3, val_name='user_name')
        self.__validate(pwd_hash, str, minlen=1, val_name='password_hash')
        self.__validate(roles, list, minlen=1, val_name='roles', possible_vals=ROLES_DESC.keys())

        user = {DBK_USERNAME: username,
                     DBK_USER_PWD_HASH: pwd_hash,
                     DBK_ROLES: roles}
        self.__mgmt_db[DBK_USERS].insert(user)

    def remove_user(self, username):
        self.__mgmt_db[DBK_USERS].remove({DBK_USERNAME: username})

    def update_user_info(self, username, pwd_hash=None, roles=None):
        user = self.__mgmt_db[DBK_USERS].find_one({DBK_USERNAME: username})
        if not user:
            raise MENotFoundException('User "%s" does not found!'%username)

        if pwd_hash:
            self.__validate(pwd_hash, str, minlen=1, val_name='password_hash')
            user[DBK_USER_PWD_HASH] = pwd_hash

        if roles:
            self.__validate(roles, list, minlen=1, val_name='roles', possible_vals=ROLES_DESC.keys())
            user[DBK_ROLES] = roles

        self.__mgmt_db[DBK_USERS].update({DBK_USERNAME: username}, user)


    def add_session(self, session_id, username):
        self.__mgmt_db[DBK_SESSIONS].insert({DBK_ID: session_id, \
                                        DBK_USERNAME: username, \
                                        DBK_START_DT: datetime.now()})

    def del_session(self, session_id):
        self.__mgmt_db[DBK_SESSIONS].remove({DBK_ID: session_id})

    def get_user_by_session(self, session_id):
        session = self.__mgmt_db[DBK_SESSIONS].find_one({DBK_ID: session_id})
        if not session:
            return None
        username = session[DBK_USERNAME]
        user = self.get_user_info(username)
        if not user:
            return None
        return user

    def get_user_last_session(self, username):
        sessions = self.__mgmt_db[DBK_SESSIONS].find({DBK_USERNAME: username}).sort([(DBK_START_DT, -1)])
        for session in sessions:
            return session
        return None

    def append_physical_node(self, ssh_hostname, ssh_port, user_name, memory, cpumodel, cores_cnt):
        self.__mgmt_db[DBK_PHY_NODES].insert({DBK_ID: ssh_hostname, \
                                        DBK_SSHPORT: ssh_port, \
                                        DBK_USERNAME: user_name, \
                                        DBK_MEMORY: memory, \
                                        DBK_CPUMODEL: cpumodel, \
                                        DBK_CORESCNT: cores_cnt, \
                                        DBK_INSTALLDATE: datetime.now()})

    def get_physical_node(self, ssh_hostname):
        return self.__mgmt_db[DBK_PHY_NODES].find_one({DBK_ID: ssh_hostname})

    def get_physical_nodes(self, filter_map={}):
        return self.__mgmt_db[DBK_PHY_NODES].find(filter_map)

    def remove_physical_node(self, ph_node_host):
        self.__mgmt_db[DBK_PHY_NODES].remove({DBK_ID: ph_node_host})

    def append_fabnet_node(self, ph_node_host, node_name, node_type, node_addr, home_dir_name):
        self.__mgmt_db[DBK_NODES].insert({DBK_ID: node_name, \
                                        DBK_PHNODEID: ph_node_host, \
                                        DBK_NODETYPE: node_type, \
                                        DBK_NODEADDR: node_addr, \
                                        DBK_HOMEDIR: home_dir_name, \
                                        DBK_INSTALLDATE: datetime.now()})

    def update_fabnet_node(self, node_obj):
        self.__mgmt_db[DBK_NODES].update({DBK_ID: node_obj[DBK_ID]}, node_obj)

    def get_fabnet_node(self, node_name):
        return self.__mgmt_db[DBK_NODES].find_one({DBK_ID: node_name})

    def get_fabnet_nodes(self, filter_map={}):
        return self.__mgmt_db[DBK_NODES].find(filter_map)

    def remove_fabnet_node(self, node_name):
        self.__mgmt_db[DBK_NODES].remove({DBK_ID: node_name})

    def __check_node_name(self, node_name):
        if node_name:
            node = self.get_fabnet_node(node_name)
            if not node:
                raise MENotFoundException('Node "%s" does not found!'%node_name)
        else:
            node_name = None
        return node_name

    def set_config(self, node_name, config):
        node_name = self.__check_node_name(node_name)

        for key, value in config.items():
            item = self.__mgmt_db[DBK_CLUSTER_CONFIG].find_one( \
                    {DBK_NODE_NAME: node_name, DBK_CONFIG_PARAM: key})
            if item:
                self.__mgmt_db[DBK_CLUSTER_CONFIG].update({DBK_ID: item[DBK_ID]}, \
                        {'$set': {DBK_CONFIG_VALUE: value}})
            else:
                cf_item = {DBK_CONFIG_PARAM: key,
                            DBK_CONFIG_VALUE: value,
                            DBK_NODE_NAME: node_name}
                self.__mgmt_db[DBK_CLUSTER_CONFIG].insert(cf_item)

    def get_config(self, node_name, ret_all=False):
        node_name = self.__check_node_name(node_name)
        config = self.__mgmt_db[DBK_CLUSTER_CONFIG].find({DBK_NODE_NAME: node_name})
        if node_name and ret_all:
            ret_config = self.get_config(node_name=None) #get global config
        else:
            ret_config = {}

        for item in config:
            ret_config[item[DBK_CONFIG_PARAM]] = item[DBK_CONFIG_VALUE]
        return ret_config


    def set_release(self, node_type, release_url, version):
        found = self.__mgmt_db[DBK_RELEASES].find_one({DBK_ID: node_type})
        if found:
            found[DBK_RELEASE_URL] = release_url
            found[DBK_RELEASE_VERSION] = version
            self.__mgmt_db[DBK_RELEASES].update({}, found, upsert=True)
        else:
            self.__mgmt_db[DBK_RELEASES].insert({DBK_ID: node_type, \
                    DBK_RELEASE_URL: release_url, \
                    DBK_RELEASE_VERSION: version})

    def get_releases(self):
        return self.__mgmt_db[DBK_RELEASES].find({})




    
    def get_nodes_list(self, status):
        recs = self.__mgmt_db[DBK_NODES].find({DBK_STATUS: status}, [DBK_NODEADDR])
        return [rec[DBK_NODEADDR] for rec in recs]


    def change_node_status(self, nodeaddr, status):
        nodeobj = self.__mgmt_db[DBK_NODES].find_one({DBK_NODEADDR: nodeaddr})
        if nodeobj:
            nodeobj[DBK_STATUS] = status
            self.update_fabnet_node(nodeobj)

    def update_node_info(self, nodeaddr, node_name, home_dir, node_type, superior_neighbours, upper_neighbours):
        #superiors = ','.join(superior_neighbours)
        #uppers = ','.join(upper_neighbours)
        nodeobj = self.get_fabnet_node(node_name)
        if nodeobj:
            nodeobj[DBK_NODEADDR] = nodeaddr
            nodeobj[DBK_SUPERIORS] = superior_neighbours
            nodeobj[DBK_UPPERS] = upper_neighbours
            nodeobj[DBK_STATUS] = STATUS_UP
            self.update_fabnet_node(nodeobj)
        else:
            raise Exception('Node "%s" does not found in database'%node_name)

    def update_node_stat(self, nodeaddr, stat):
        self.__mgmt_db[DBK_NODES].update({DBK_NODEADDR: nodeaddr}, {'$set': \
                {DBK_STATISTIC: stat, DBK_STATUS: STATUS_UP, DBK_LAST_CHECK: datetime.now()}})

    def notification(self, notify_provider, notify_type, notify_topic, message, date):
        self.__mgmt_db[DBK_NOTIFICATIONS].insert({DBK_NODEADDR: notify_provider,
                                                    DBK_NOTIFY_TYPE: notify_type,
                                                    DBK_NOTIFY_TOPIC: notify_topic,
                                                    DBK_NOTIFY_MSG: message,
                                                    DBK_NOTIFY_DT: date})

