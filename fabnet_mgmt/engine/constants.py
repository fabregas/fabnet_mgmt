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
DBK_CONFIG_CA_ADDR = 'ca_address'
DBK_CONFIG_CA_DB = '__ca_db_conn'
DBK_CONFIG_SSH_KEY = '__ssh_key'
DBK_CONFIG_SECURED_INST = '__is_secured_installation' 
DBK_CONFIG_MGMT_KS = '__mgmt_ks'
DBK_UPGRADE_FLAG = '__upgrade_flag'
DBK_SCHEDULED_DUMP = '__sch_dump'

DBK_RELEASES = 'releases'
DBK_RELEASE_URL = 'release_url'
DBK_RELEASE_VERSION = 'release_version'

DBK_USERNAME = 'username'
DBK_HOMEDIR = 'homedir'
DBK_PHNODEID = 'ph_node_id'
DBK_START_DT = 'start_dt'
DBK_ROLES = 'roles'
DBK_USER_PWD_HASH = 'password_hash'
DBK_LAST_SESSION = 'last_session'
DBK_STATUS = 'status'

DBK_SSHPORT = 'ssh_port'
DBK_USERNAME = 'user_name'

DBK_PHY_NODES = 'physical_nodes'
DBK_NODES = 'installed_nodes'
DBK_NODETYPE = 'node_type'
DBK_NODEADDR = 'node_addr'
DBK_INSTALLDATE = 'install_date'
DBK_SUPERIORS = 'superior_nodes'
DBK_UPPERS = 'upper_nodes'
DBK_STATISTIC = 'statistic'
DBK_LAST_CHECK = 'last_check'
DBK_KS_DATA = 'ks_data'
DBK_KS_PWD_ENCR = 'ks_pwd_enc'

DBK_MEMORY = 'memory'
DBK_CPUMODEL = 'cpu_model'
DBK_CORESCNT = 'cores_count'

DBK_CONFIG_PARAM = 'config_param'
DBK_CONFIG_VALUE = 'config_value'
DBK_NODE_NAME = 'node_name'

DBK_NOTIFICATIONS = 'notifications'
DBK_NOTIFY_TOPIC = 'notify_topic'
DBK_NOTIFY_MSG = 'notify_mgs'
DBK_NOTIFY_TYPE = 'notify_type'
DBK_NOTIFY_DT = 'notify_dt'


#node statuses
STATUS_UP = 1
STATUS_DOWN = 0

#user roles
ROLE_RO = 'readonly'
ROLE_UM = 'usersmanage'
ROLE_NM = 'nodesmanage'
ROLE_CF = 'configure'
ROLE_SS = 'startstop'
ROLE_UPGR = 'upgrade'

#user name for nodes
USER_NAME = 'fabnet'

MGMT_NODE_TYPE = 'MGMT'

ROLES_DESC = {ROLE_RO: 'Read only access',
            ROLE_UM: 'Manage users accounts access',
            ROLE_NM: 'Manage cluster nodes (install, remove)',
            ROLE_CF: 'Configure cluster access',
            ROLE_SS: 'Start/Stop/Reload nodes access',
            ROLE_UPGR: 'Upgrade nodes access'}

