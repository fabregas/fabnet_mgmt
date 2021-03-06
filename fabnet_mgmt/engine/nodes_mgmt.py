import os
import re
import base64
import urllib2
import zipfile
import tempfile

from fabnet_mgmt.engine.decorators import MgmtApiMethod
from fabnet_mgmt.engine.constants import ROLE_RO, ROLE_CF, ROLE_SS, ROLE_NM, \
        USER_NAME, DBK_ID, DBK_PHNODEID, DBK_RELEASE_URL, DBK_SSHPORT, DBK_KS_PWD_ENCR, MGMT_NODE_TYPE, \
        DBK_HOMEDIR, DBK_NODETYPE, DBK_STATUS, DBK_NODEADDR, STATUS_UP, STATUS_DOWN, DBK_UPGRADE_FLAG, \
        DBK_CONFIG_NODE_NUMSCNT, DBK_CONFIG_CLNAME
from fabnet_mgmt.engine.exceptions import MEAlreadyExistsException, \
        MEOperException, MENotFoundException, MEBadURLException 

FABNET_INSTALLER_PATH = '/opt/blik/fabnet/bin/pkg-install'

def to_mb(str_val):
    parts = str_val.split()
    if len(parts) != 2:
        raise Exception('to_gb error: invalid argument "%s"'%str_val)
    val, m = parts
    val = float(val)
    if m.lower() == 'kb':
        return int(val)/1000.
    elif m.lower() == 'mb':
        return val
    elif m.lower() == 'gb':
        return val*1000.
    raise Exception('to_gb error: invalid argument "%s"'%str_val)

@MgmtApiMethod(ROLE_NM)
def install_physical_node(engine, session_id, ssh_address, ssh_user, ssh_pwd, ssh_key):
    ssh_cli = engine.get_ssh_client()
    if ':' in ssh_address:
        ssh_address, port = ssh_address.split(':')
        port = int(port)
    else:
        port = 22

    node = engine.db_mgr().get_physical_node(ssh_address)
    if node:
        raise MEAlreadyExistsException('Physical node "%s" is already exists in database!'%ssh_address) 

    cli_inst = ssh_cli.connect(ssh_address, port, ssh_user, ssh_pwd, ssh_key)
    
    try:
        cli_inst.execute('sudo useradd -m %s'%(USER_NAME,))
        cli_inst.execute('sudo groupadd %s'%(USER_NAME,))
        cli_inst.execute('sudo usermod -a -G wheel %s'%(USER_NAME,))
        cli_inst.safe_exec('sudo [ -d /home/%s/.ssh ] || (sudo mkdir /home/%s/.ssh; sudo chmod 700 /home/%s/.ssh)'%(USER_NAME, USER_NAME, USER_NAME))
        cli_inst.safe_exec('echo "ssh-rsa %s" | sudo tee -a /home/%s/.ssh/authorized_keys'%(ssh_cli.get_pubkey(), USER_NAME))
        cli_inst.safe_exec('sudo chmod 600 /home/%s/.ssh/authorized_keys'%(USER_NAME,))
        cli_inst.safe_exec('sudo chown %s:%s -R /home/%s/.ssh/'%(USER_NAME, USER_NAME, USER_NAME))
        cli_inst.safe_exec('sudo mkdir -p /opt/blik/fabnet/packages')
        cli_inst.safe_exec('sudo chown %s:%s -R /opt/blik/fabnet'%(USER_NAME, USER_NAME))
    finally:
        cli_inst.close()

    #check connection with system ssh key
    ssh_cli = engine.get_ssh_client()
    cli_inst = ssh_cli.connect(ssh_address, port, USER_NAME)
    try:
        cli_inst.safe_exec('grep MemTotal /proc/meminfo')
        parts = cli_inst.output.split('\n')[0].split(':')
        if len(parts) != 2:
            raise Exception('/proc/meminfo error! %s'%cli_inst.output)
        mem = parts[1].strip()
        mem = to_mb(mem)
        
        cli_inst.safe_exec('grep "model name" /proc/cpuinfo')
        cores = cli_inst.output.strip().split('\n')
        parts = cores[0].split(':')
        if len(parts) != 2:
            raise Exception('/proc/cpuinfo error!')
        cpu_model = parts[1]
        cpu_model = ' '.join(cpu_model.split())
        cores = cli_inst.output.count('model name')
    finally:
        cli_inst.close()
    
    engine.db_mgr().append_physical_node(ssh_address, port, USER_NAME, mem, cpu_model, cores)
    return ssh_address

@MgmtApiMethod(ROLE_NM)
def remove_physical_node(engine, session_id, ph_node_host):
    f_nodes = engine.db_mgr().get_fabnet_nodes({DBK_PHNODEID: ph_node_host})
    if f_nodes.count():
        raise MEOperException('Physical node "%s" contain configured fabnet node(s)!'%ph_node_host)

    node = engine.db_mgr().get_physical_node(ph_node_host)
    if not node:
        raise MENotFoundException('Physical node "%s" does not installed'%ph_node_host) 

    engine.db_mgr().remove_physical_node(ph_node_host)

@MgmtApiMethod(ROLE_NM)
def get_ssh_key(engine, session_id, ph_node_host=None):
    ssh_cli = engine.get_ssh_client()
    return 'ssh-rsa %s' % ssh_cli.get_pubkey()

@MgmtApiMethod(ROLE_NM)
def install_fabnet_node(engine, session_id, ph_node_host, node_type, node_addr, force_sw_upgrade=True, node_name=None):
    max_node_num = engine.db_mgr().get_max_fabnet_node_num()
    node_num = max_node_num + 1

    if node_name:
        node_name = node_name.lower()
    else:
        num_cnt = engine.get_config_var(DBK_CONFIG_NODE_NUMSCNT)
        cluster_name = engine.get_config_var(DBK_CONFIG_CLNAME)
        node_name = '%s%s'%(cluster_name, str(node_num).zfill(num_cnt))

    node_type = node_type.upper()
    
    if not re.match('\w+$', node_name):
        raise MEOperException('Invalid node name "%s"!'%node_name)

    node = engine.db_mgr().get_physical_node(ph_node_host)
    if not node:
        raise MENotFoundException('Physical node "%s" does not installed'%ph_node_host) 

    f_node = engine.db_mgr().get_fabnet_node(node_name)
    if f_node:
        raise MEAlreadyExistsException('Node "%s" is already exists in database!'%node_name) 

    releases = engine.db_mgr().get_releases()
    release_url = None
    for release in releases:
        if node_type == release[DBK_ID]:
            release_url = release[DBK_RELEASE_URL] 
            break

    if not release_url:
        raise MENotFoundException('Node type "%s" does not configured in the system!'%node_type)
    
    if engine.is_secured_installation():
        ks_path, ks_pwd_enc = engine.generate_node_key_storage(node_addr)
        ks_data = base64.b64encode(open(ks_path, 'rb').read())
    else:
        ks_path = ks_data = ks_pwd_enc = None

    home_dir_name = '%s_node_home' % node_name
    
    ssh_cli = engine.get_ssh_client()
    cli_inst = ssh_cli.connect(ph_node_host, node[DBK_SSHPORT], USER_NAME)
    sftp = cli_inst.open_sftp()
    try:
        sftp.put(FABNET_INSTALLER_PATH, '/home/%s/installer.py'%USER_NAME)

        force = '--force' if force_sw_upgrade else ''
        cli_inst.safe_exec('python /home/%s/installer.py %s %s'%(USER_NAME, release_url, force))
        cli_inst.safe_exec('mkdir -p %s'%home_dir_name)
        if ks_path:
            #save CA certs
            cli_inst.safe_exec('echo "%s" > /home/%s/%s/certs.ca'%(engine.get_ca_certificates(), USER_NAME, home_dir_name))

            #copy ks to node
            sftp.put(ks_path, '/home/%s/%s/%s_ks.p12'%(USER_NAME, home_dir_name, node_name))
            os.unlink(ks_path)
    finally:
        sftp.close()
        cli_inst.close()
    
    engine.db_mgr().append_fabnet_node(ph_node_host, node_num, node_name, node_type, \
            node_addr, '/home/%s/%s'%(USER_NAME, home_dir_name), ks_data, ks_pwd_enc)
    return node_name

@MgmtApiMethod(ROLE_NM)
def remove_fabnet_node(engine, session_id, node_name):
    node_name = node_name.lower()
    f_node = engine.db_mgr().get_fabnet_node(node_name)
    if not f_node:
        raise MENotFoundException('Node "%s" does not installed'%node_name) 
    
    engine.db_mgr().remove_fabnet_node(node_name)

@MgmtApiMethod(ROLE_RO)
def show_nodes(engine, session_id, filters={}, rows=None):
    '''
    filters:
        physical (bool) - get info about physical nodes
        node_type (str) - filter nodes by node_type
    '''
    is_phys = filters.get('physical', False)
    if is_phys:
        data = engine.db_mgr().get_physical_nodes()
    else:
        filter_exp = {}
        if 'node_type' in filters:
            filter_exp = {'node_type': filters['node_type']}
        data = engine.db_mgr().get_fabnet_nodes(filter_exp)

    ret_data = []
    for item in data:
        ret_data.append(dict(item))
    return ret_data

@MgmtApiMethod(ROLE_NM)
def set_release(engine, session_id, node_type, release_url):
    try:
        response = urllib2.urlopen(release_url)
        zip_content = response.read()
    except Exception, err:
        raise MEBadURLException('Bad release URL "%s" for node type "%s"!' \
                                                    %(release_url, node_type)) 

    f_obj = tempfile.NamedTemporaryFile()
    try:
        f_obj.write(zip_content)
        f_obj.flush()
        with zipfile.ZipFile(f_obj.name) as z_file:
            for item in z_file.namelist():
                if item.endswith('VERSION') and item.count('/') == 1:
                    version = z_file.read(item)
                    version = version.strip()
                    break
            else:
                version = 'unknown'
    finally:
        f_obj.close()

    node_type = node_type.upper()
    engine.db_mgr().set_release(node_type, release_url, version)

@MgmtApiMethod(ROLE_RO)
def get_releases(engine, session_id):
    data = engine.db_mgr().get_releases()
    ret_data = []
    for item in data:
        ret_data.append(dict(item))
    return ret_data

@MgmtApiMethod(ROLE_CF)
def apply_config(engine, session_id, node_name):
    if node_name:
        node_name = node_name.lower()
        node_objs = engine.db_mgr().get_fabnet_nodes({DBK_ID: node_name})
        if not node_objs.count():
            raise MENotFoundException('Node "%s" does not found!'%node_name) 

    node_objs = engine.db_mgr().get_fabnet_nodes({})

    for node in node_objs:
        config = engine.db_mgr().get_config(node_name, ret_all=True)
        __set_config_to_node(node[DBK_NODEADDR], config)
    

def __start_node(engine, node, config, neighbour):
    #prepare config
    config_str = ''
    config['node_type'] = node[DBK_NODETYPE]
    config['node_name'] = node[DBK_ID]
    parts = node[DBK_NODEADDR].split(':')
    config['fabnet_node_host'] = parts[0] 
    if len(parts) > 1:
        config['fabnet_node_port'] = parts[1]

    for key, value in config.items():
        if key.startswith('_'):
            continue
        config_str += "%s = '%s'\n"%(key, value)

    ssh_cli = engine.get_ssh_client()
    ph_node = engine.db_mgr().get_physical_node(node[DBK_PHNODEID])
    cli_inst = ssh_cli.connect(ph_node[DBK_ID], ph_node[DBK_SSHPORT], USER_NAME)

    cmd = 'echo "%s" > %s/fabnet.conf'%(config_str, node[DBK_HOMEDIR])
    cli_inst.safe_exec(cmd)

    cmd = 'FABNET_NODE_HOME="%s" /opt/blik/fabnet/bin/node-daemon start %s --input-pwd' \
            %(node[DBK_HOMEDIR], neighbour)

    if engine.is_secured_installation():
        password = engine.decrypt_password(node[DBK_KS_PWD_ENCR])
    else:
        password = None
    try:
        rcode = cli_inst.execute(cmd, input_str=password)
    finally:
        cli_inst.close()

    if rcode == 0:
        return ''
    if rcode == 11:
        return 'Node %s is already started'%node[DBK_ID]
    raise MEOperException('\n# %s\n%s\nERROR! Node does not started!'%(cmd, cli_inst.output))

def __stop_node(engine, node):
    ssh_cli = engine.get_ssh_client()
    ph_node = engine.db_mgr().get_physical_node(node[DBK_PHNODEID])
    cli_inst = ssh_cli.connect(ph_node[DBK_ID], ph_node[DBK_SSHPORT], USER_NAME)
    cmd = 'FABNET_NODE_HOME="%s" /opt/blik/fabnet/bin/node-daemon stop'%node[DBK_HOMEDIR]
    if node[DBK_NODEADDR] == engine.self_node_address:
        cmd += ' --nowait'

    try:
        rcode = cli_inst.execute(cmd)
    finally:
        cli_inst.close()

    if rcode == 0:
        return ''
    if rcode == 20:
        return 'Node %s is already stopped'%node[DBK_ID]
    raise MEOperException('\n# %s\n%s\nERROR! Node does not stopped!'%(cmd, cli_inst.output))

def __upgrade_node(engine, node, force):
    ssh_cli = engine.get_ssh_client()
    ph_node = engine.db_mgr().get_physical_node(node[DBK_PHNODEID])
    cli_inst = ssh_cli.connect(ph_node[DBK_ID], ph_node[DBK_SSHPORT], USER_NAME)

    if node[DBK_NODETYPE].upper() == MGMT_NODE_TYPE:
        releases = engine.db_mgr().get_releases()
    else:
        release = engine.db_mgr().get_release(node[DBK_NODETYPE])
        if not release:
            return
        releases = [release]

    for release in releases:
        release_url = release[DBK_RELEASE_URL]
        cmd = 'sudo /opt/blik/fabnet/bin/pkg-install %s %s'%(release_url, '--force' if force else '')
        cli_inst.safe_exec(cmd)

def get_nodes_objs(engine, nodes_list, need_sort=False):
    nodes_objs = []
    if nodes_list:
        for node_name in nodes_list:
            node_name = node_name.lower()
            items = engine.db_mgr().get_fabnet_nodes({DBK_ID: node_name})
            if not items.count():
                raise MENotFoundException('Node "%s" does not found!'%node_name) 
            nodes_objs.append(items[0])
    else:
        nodes_objs = engine.db_mgr().get_fabnet_nodes({})

    if not need_sort:
        return nodes_objs

    sorted_objs = []
    mgmt_nodes = []
    for node_obj in nodes_objs:
        if node_obj[DBK_NODETYPE] == MGMT_NODE_TYPE:
            mgmt_nodes.append(node_obj)
        else:
            sorted_objs.append(node_obj)

    sorted_objs.sort(key=lambda obj: obj[DBK_ID])
    sorted_objs += mgmt_nodes
    return sorted_objs

@MgmtApiMethod(ROLE_SS)
def start_nodes(engine, session_id, nodes_list=[], log=None, wait_routine=None, reboot=False):
    nodes_objs = get_nodes_objs(engine, nodes_list)
    ret_str = ''
    for i, node_obj in enumerate(nodes_objs):
        need_upgr = node_obj.get(DBK_UPGRADE_FLAG, False)
        if need_upgr:
            __log(log, 'Upgrading %s node ...'%node_obj[DBK_ID])
            __upgrade_node(engine, node_obj, need_upgr == 'need_force')
            
        config = engine.db_mgr().get_config(node_obj[DBK_ID], ret_all=True)
        up_nodes = engine.db_mgr().get_fabnet_nodes({DBK_STATUS: STATUS_UP})
        up_nodes.limit(1)
        neighbour = None
        for node in up_nodes:
            n_id = node[DBK_NODEADDR]
            if n_id != node_obj[DBK_NODEADDR]:
                neighbour = n_id
                break

        if not neighbour:
            neighbour = 'init-fabnet'

        if reboot:
            if node_obj[DBK_NODETYPE] == MGMT_NODE_TYPE:
                __log(log, 'Skipped management node %s reboot!'%node_obj[DBK_ID])
                continue
            __log(log, 'Rebooting %s node ...'%node_obj[DBK_ID])
        else:
            __log(log, 'Starting %s node ...'%node_obj[DBK_ID])

        try:
            if reboot:
                ret_str = __stop_node(engine, node_obj)
            ret_str = __start_node(engine, node_obj, config, neighbour)
            if ret_str:
                __log(log, ret_str)
            else:
                __log(log, 'Done.')
        except Exception, err:
            __log(log, 'Error: %s'%err)

        try:
            if wait_routine:
                wait_routine(i, node_obj)
        except Exception, err:
            __log(log, 'Wait %s node stop error: %s'%(node_obj[DBK_ID], err))

        node_obj[DBK_STATUS] = STATUS_UP
        node_obj[DBK_UPGRADE_FLAG] = False
        engine.db_mgr().update_fabnet_node(node_obj)


@MgmtApiMethod(ROLE_SS)
def stop_nodes(engine, session_id, nodes_list=[], log=None, wait_routine=None):
    nodes_objs = get_nodes_objs(engine, nodes_list, need_sort=True)

    for i, node_obj in enumerate(nodes_objs):
        __log(log, 'Stopping %s node ...'%node_obj[DBK_ID])
        try:
            ret_str = __stop_node(engine, node_obj)
            if ret_str:
                __log(log, ret_str)
            else:
                __log(log, 'Done.')
        except Exception, err:
            __log(log, 'Error: %s'%err)

        try:
            if wait_routine:
                wait_routine(i, node_obj)
        except Exception, err:
            __log(log, 'Wait %s node stop error: %s'%(node_obj[DBK_ID], err))

        node_obj[DBK_STATUS] = STATUS_DOWN
        engine.db_mgr().update_fabnet_node(node_obj)


@MgmtApiMethod(ROLE_RO)
def get_nodes_stat(engine, session_id, nodes_list=[]):
    nodes_objs = get_nodes_objs(engine, nodes_list)
    ret_list = {}
    for node_obj in nodes_objs:
        if node_obj.get(DBK_STATUS, STATUS_DOWN) == STATUS_DOWN:
            stat = {}
        else:
            stat = node_obj.get('statistic', {})
        ret_list[node_obj[DBK_ID]] = stat 
    return ret_list

def __log(log_obj, message):
    if log_obj:
        log_obj.write(message+'\n')

@MgmtApiMethod(ROLE_SS)
def software_upgrade(engine, session_id, force=False, log=None):
    #mark all down nodes with upgrade flag
    nodes = engine.db_mgr().get_fabnet_nodes(filter_map={DBK_STATUS: STATUS_DOWN})
    for node in nodes:
        node[DBK_UPGRADE_FLAG] = 'need_force' if force else 'need'
        engine.db_mgr().update_fabnet_node(node)

    #call upgrade operation over fabnet
    __log(log, 'Calling upgrade operation over network asynchronously ...')
    releases = engine.db_mgr().get_releases()
    rel_map = {}
    for release in releases:
        rel_map[release[DBK_ID].upper()] = release[DBK_RELEASE_URL]
    rel_map[MGMT_NODE_TYPE] = rel_map.values()

    parameters={'releases': rel_map, 'force': force}

    ret_code, ret_msg = engine.fri_call_net(None, 'UpgradeNode', parameters)
    if ret_code:
        raise Exception('Unable to call UpgradeNode operation: %s'%ret_msg)


