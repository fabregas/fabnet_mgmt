#!/usr/bin/python
"""
Copyright (C) 2013 Konstantin Andrusenko
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.

@package mgmt_engine.constants
@author Konstantin Andrusenko
@date July 24, 2013
"""

#database keys
DBK_CLUSTER_CONFIG = 'cluster_config'
DBK_USERS = 'users'
DBK_SESSIONS = 'sessions'

DBK_ID = '_id'
DBK_CONFIG_CLNAME = 'cluster_name'
DBK_CONFIG_SECURED_INST = '__is_secured_installation' 
DBK_CONFIG_SSH_KEY = '__ssh_key'
DBK_CONFIG_NODE_GIT_REPO = '__git_repo_url'
DBK_CONFIG_CA_ADDR = '__ca_addr'

DBK_USERNAME = 'username'
DBK_START_DT = 'start_dt'
DBK_ROLES = 'roles'
DBK_USER_PWD_HASH = 'password_hash'
DBK_LAST_SESSION = 'last_session'

DBK_NODES = 'installed_nodes'
DBK_NODETYPE = 'node_type'
DBK_NODEADDR = 'node_addr'
DBK_INSTALLDATE = 'install_date'

#user roles
ROLE_RO = 'readonly'
ROLE_UM = 'usersmanage'
ROLE_NM = 'nodesmanage'
ROLE_CF = 'configure'
ROLE_SS = 'startstop'
ROLE_UPGR = 'upgrade'

ROLES_DESC = {ROLE_RO: 'Read only access',
            ROLE_UM: 'Manage users accounts access',
            ROLE_NM: 'Manage cluster nodes (install, remove)',
            ROLE_CF: 'Configure cluster access',
            ROLE_SS: 'Start/Stop/Reload nodes access',
            ROLE_UPGR: 'Upgrade nodes access'}

