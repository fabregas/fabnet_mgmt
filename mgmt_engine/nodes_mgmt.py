
from mgmt_engine.decorators import *
from mgmt_engine.constants import *
from mgmt_engine.exceptions import *
###import paramiko


@mgmt_api_method(ROLE_RO)
def get_cluster_config(engine, session_id):
    return engine._db_mgr.get_cluster_config()

@mgmt_api_method(ROLE_CF)
def configure_cluster(engine, session_id, config):
    engine._db_mgr.set_cluster_config(config)

@mgmt_api_method(ROLE_NM)
def install_physical_node(engine, session_id, ssh_address, ssh_user, ssh_pwd, ssh_key):
    node = engine._db_mgr.get_physical_node(ssh_address)
    if node:
        raise MEAlreadyExistsException('Physical node "%s" is already exists in database!'%ssh_address) 

    ssh_cli = engine.get_ssh_client()
    if ':' in ssh_address:
        ssh_address, port = ssh_address.split(':')
        port = int(port)
    else:
        port = 22
    cli_inst = ssh_cli.connect(ssh_address, port, ssh_user, ssh_pwd, ssh_key)
    
    cli_inst.execute('sudo useradd -m %s'%(USER_NAME,))
    cli_inst.execute('sudo groupadd %s'%(USER_NAME,))
    cli_inst.execute('sudo usermod -a -G wheel %s'%(USER_NAME,))
    cli_inst.safe_exec('sudo [ -d /home/%s/.ssh ] || (sudo mkdir /home/%s/.ssh; sudo chmod 700 /home/%s/.ssh)'%(USER_NAME, USER_NAME, USER_NAME))
    cli_inst.safe_exec('echo "ssh-rsa %s" | sudo tee -a /home/%s/.ssh/authorized_keys'%(ssh_cli.get_pubkey(), USER_NAME))
    cli_inst.safe_exec('sudo chmod 600 /home/%s/.ssh/authorized_keys'%(USER_NAME,))
    cli_inst.safe_exec('sudo chown %s:%s -R /home/%s/.ssh/'%(USER_NAME, USER_NAME, USER_NAME))
    cli_inst.safe_exec('sudo yum install -y git || apt-get install git')
    cli_inst.close()

    #check connection with system ssh key
    ssh_cli = engine.get_ssh_client()
    cli_inst = ssh_cli.connect(ssh_address, port, USER_NAME)
    cli_inst.safe_exec('ls -la')
    #cli_inst.safe_exec('git clone .. node_repo')
    #cli_inst.safe_exec('cd node_repo')
    #cli_inst.safe_exec('make install')
    cli_inst.close()
    
    engine._db_mgr.append_physical_node(ssh_address, port, USER_NAME)
    return ssh_address

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


