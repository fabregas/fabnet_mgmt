
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


def to_gb(str_val):
    parts = str_val.split()
    if len(parts) != 2:
        raise Exception('to_gb error: invalid argument "%s"'%str_val)
    val, m = parts
    val = int(val)
    if m.lower() == 'kb':
        return int(val)/1000./1000.
    elif m.lower() == 'mb':
        return val/1000.
    elif m.lower() == 'gb':
        return val
    raise Exception('to_gb error: invalid argument "%s"'%str_val)

@mgmt_api_method(ROLE_NM)
def install_physical_node(engine, session_id, ssh_address, ssh_user, ssh_pwd, ssh_key):
    ssh_cli = engine.get_ssh_client()
    if ':' in ssh_address:
        ssh_address, port = ssh_address.split(':')
        port = int(port)
    else:
        port = 22

    node = engine._db_mgr.get_physical_node(ssh_address)
    if node:
        raise MEAlreadyExistsException('Physical node "%s" is already exists in database!'%ssh_address) 

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
    cli_inst.safe_exec('grep MemTotal /proc/meminfo')
    parts = cli_inst.output.split(':')
    if len(parts) != 2:
        raise Exception('/proc/meminfo error!')
    mem = parts[1].strip()
    mem = to_gb(mem)
    
    cli_inst.safe_exec('grep "model name" /proc/cpuinfo')
    cores = cli_inst.output.strip().split('\n')
    parts = cores[0].split(':')
    if len(parts) != 2:
        raise Exception('/proc/cpuinfo error!')
    cpu_model = parts[1]
    cpu_model = ' '.join(cpu_model.split())
    
    #cli_inst.safe_exec('git clone .. node_repo')
    #cli_inst.safe_exec('cd node_repo')
    #cli_inst.safe_exec('make install')
    cli_inst.close()
    
    engine._db_mgr.append_physical_node(ssh_address, port, USER_NAME, mem, cpu_model, len(cores))
    return ssh_address


@mgmt_api_method(ROLE_RO)
def show_nodes(engine, session_id, filters={}, rows=None):
    '''
    filters:
        physical (bool) - get info about physical nodes
        node_type (str) - filter nodes by node_type
    '''
    is_phys = filters.get('physical', False)
    if is_phys:
        data = engine._db_mgr.get_physical_nodes()
    else:
        raise Exception('not implemented')

    ret_data = []
    for item in data:
        ret_data.append(dict(item))
    return ret_data




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


