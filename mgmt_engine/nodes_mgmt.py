
from mgmt_engine.decorators import *
from mgmt_engine.constants import *
from mgmt_engine.exceptions import *
###import paramiko

@mgmt_api_method(ROLE_RO)
def get_cluster_config(self, session_id):
    return self._db_mgr.get_cluster_config()

@mgmt_api_method(ROLE_CF)
def configure_cluster(self, session_id, config):
    self._db_mgr.set_cluster_config(config)

@mgmt_api_method(ROLE_NM)
def install_new_node(self, session_id, ssh_address, ssh_user, ssh_pwd, node_name, \
        node_type, node_address):
    client = paramiko.SSHClient()
    client.get_host_keys().add(ssh_address, 'ssh-rsa', paramiko.RSAKey.generate(1024))
    client.connect(ssh_address, username=ssh_user, password=ssh_pwd)
    stdin, stdout, stderr = client.exec_command('ls')

    #sftp = s.open_sftp()
    #sftp.put('/home/me/file.ext', '/remote/home/file.ext')
    self._db_mgr.append_node(node_name, node_type, node_address)

@mgmt_api_method(ROLE_SS)
def show_nodes(self, session_id, filters={}, rows=None):
    pass

@mgmt_api_method(ROLE_SS)
def start_nodes(self, session_id, nodes_list=[]):
    pass

@mgmt_api_method(ROLE_SS)
def reload_nodes(self, session_id, nodes_list=[]):
    pass

@mgmt_api_method(ROLE_SS)
def stop_nodes(self, session_id, nodes_list=[]):
    pass

@mgmt_api_method(ROLE_SS)
def upgrade_nodes(self, session_id):
    pass


