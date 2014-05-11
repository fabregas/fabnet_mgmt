#!/usr/bin/python
"""
Copyright (C) 2014 Konstantin Andrusenko
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.

@package mgmt_cli.nodes_mgmt_cli
@author Konstantin Andrusenko
@date February 3, 2014
"""

from fabnet_mgmt.cli.decorators import cli_command
from fabnet_mgmt.engine.constants import *
from fabnet_mgmt.engine.exceptions import MENotFoundException, MEInvalidArgException

import os
import urllib2
import tempfile
import argparse

class ThrowingArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise MEInvalidArgException(message)

    def exit(self, status=0, message=None):
        if message:
            raise MEInvalidArgException(message)

def download_url(url):
    if url.lower().startswith('http:/') or url.lower().startswith('ftp:/'):
        file_o = urllib2.urlopen(url)
        data = file_o.read()
        file_o.close()
        return data
    elif url.lower().startswith('file:/'):
        path = url[6:]
        if not os.path.exists(path):
            raise MENotFoundException('Local file "%s" does not found!'%path)
        return open(path).read()
    else:
        raise MEInvalidArgException('Unsupported URL type!')


class NodesMgmtCLIHandler:
    @cli_command(20, 'show-ssh-key', 'get_ssh_key', 'sh-sshkey')
    def command_show_ssh_key(self, params):
        '''
        Show management SSL key 
        This command shows managemet SSL key that should be installed
        on every physical node for allowing access to it from management server
        '''
        key = self.mgmtManagementAPI.get_ssh_key(self.session_id)

        self.writeresponse('\n%s\n'%key)

    @cli_command(21, 'show-releases', 'get_releases', 'sh-releases')
    def command_show_releases(self, params):
        '''
        Show information about software releases 
        This command shows list of configured node types
        and software releases URLs and versions
        '''
        releases = self.mgmtManagementAPI.get_releases(self.session_id)

        self.writeresponse('-'*100)
        self.writeresponse('{:15} {:^15} {:}'.format('Node type', 'Version', 'Release URL'))
        self.writeresponse('-'*100)
        for release in releases:
            self.writeresponse('{:15} {:^15} {:}'.format(release[DBK_ID], release[DBK_RELEASE_VERSION], release[DBK_RELEASE_URL]))

    @cli_command(22, 'set-release', 'set_release', validator=(str, str))
    def command_set_release(self, params):
        '''<node type> <release url>
        Set new software releases for node type 
        This command setup software release endpoint for node type
        '''
        self.mgmtManagementAPI.set_release(self.session_id, params[0], params[1])
        self.writeresponse('New software release is installed. You can install new and upgrade exists nodes with type "%s"\n'%params[0])

    @cli_command(23, 'install-physical-node', 'install_physical_node', 'installpnode', 'i-pnode', validator=(str, str, str))
    def command_install_phy_node(self, params):
        '''<node hostname>[:<ssh port>] <ssh user name> --pwd | <ssh key url>
        Install new physical node
        This command install new physical node in management database
        and configure it for fabnet network usage
        '''
        if params[2] == '--pwd':
            pwd = self.readline(prompt='Password: ', echo=False)
            self.writeline('')
            key = None
        else:
            pwd = None
            key = download_url(params[2])

        node_host = self.mgmtManagementAPI.install_physical_node(self.session_id, \
                params[0], params[1], pwd, key)
        self.writeresponse('Node "%s" is created and configured!'%node_host)


    @cli_command(24, 'show-nodes', 'show_nodes', 'shnodes', 'shownodes')
    def command_show_nodes(self, params):
        '''[--physical|-p] [--type|-t <node type>]
        Show information about configured nodes
        This command shows information about physical and logical nodes
        that installed in the system
        '''
        parser = ThrowingArgumentParser()
        parser.add_argument('--physical', '-p', dest='is_phys', action='store_true', default=False)
        parser.add_argument('--type', '-t', dest='node_type')
        args = parser.parse_args(params)

        filters = {}
        if args.node_type:
            filters['node_type'] = args.node_type
        if args.is_phys:
            filters['physical'] = True

        nodes = self.mgmtManagementAPI.show_nodes(self.session_id, filters)

        self.writeresponse('-'*100)
        nodes = sorted(nodes, key=lambda node: node[DBK_ID])
        if args.is_phys:
            self.writeresponse('%-20s %s %s %s'%('HOSTNAME',  \
                        'MEMORY (Mb)'.center(15), 'CORES'.center(5), 'CPU MODEL'.center(60)))
            self.writeresponse('-'*100)
            for node in nodes:
                self.writeresponse('%-20s %s %s %s'%(node[DBK_ID], \
                        #node[DBK_INSTALLDATE].strftime('%d.%m.%Y %H:%M').center(20),\
                        ('%.0f'%node[DBK_MEMORY]).center(15),\
                        str(node[DBK_CORESCNT]).center(5),\
                        str(node[DBK_CPUMODEL]).center(60)))
        else:
            self.writeresponse('%-20s %s %s %s %s'%('NODE NAME',  \
                        'HOSTNAME'.center(20), 'TYPE'.center(10), 'STATUS'.center(10), 'ADDRESS'.center(20)))
            self.writeresponse('-'*100)
            for node in nodes:
                status = 'UP' if node.get(DBK_STATUS, None) == STATUS_UP else 'DOWN'
                self.writeresponse('%-20s %s %s %s %s'%(node[DBK_ID], \
                        node[DBK_PHNODEID].center(20),\
                        node[DBK_NODETYPE].center(10),\
                        status.center(10),\
                        node[DBK_NODEADDR].center(20)))

    @cli_command(25, 'install-node', 'install_fabnet_node', 'installnode', 'i-node', validator=(str,str,str,str))
    def command_install_fabnet_node(self, params):
        '''<physical node hostname> <node name> <node type> <node address>[:<custom port>]
        Install new fabnet node
        This command install new fabnet node to management database
        and configure it according to specified node type
        Node address should be hostname or IP address that is visible to other nodes in network
        '''
        self.mgmtManagementAPI.install_fabnet_node(self.session_id, params[0], params[1], params[2], params[3])
        self.writeresponse('Node "%s" is installed!'%params[1].lower())

    @cli_command(26, 'remove-physical-node', 'remove_physical_node', 'removepnode', 'rm-pnode', validator=(str,(str, 0)))
    def command_remove_phy_node(self, params):
        '''<node hostname> [--force]
        Remove physical node from the system
        This command remove physical node from management database
        if no one fabnet node configured on this physical node
        '''
        if len(params) > 1:
            if params[1] != '--force':
                raise MEInvalidArgException('Invalid argument "%s"'%params[1])
        else:
            resp = self.readline(prompt='Are you sure you want remove physical node "%s"? '%params[0], echo=True)
            if resp.lower() not in ['y', 'yes']:
                return

        self.mgmtManagementAPI.remove_physical_node(self.session_id, params[0])
        self.writeresponse('Node "%s" was removed from database!'%params[0])

    @cli_command(27, 'remove-node', 'remove_fabnet_node', 'removenode', 'rm-node', validator=(str,(str, 0)))
    def command_remove_phy_node(self, params):
        '''<node name> [--force]
        Remove fabnet node from the system
        This command remove fabnet node from management database
        '''
        if len(params) > 1:
            if params[1] != '--force':
                raise MEInvalidArgException('Invalid argument "%s"'%params[1])
        else:
            resp = self.readline(prompt='Are you sure you want remove fabnet node "%s"? '%params[0], echo=True)
            if resp.lower() not in ['y', 'yes']:
                return

        self.mgmtManagementAPI.remove_fabnet_node(self.session_id, params[0])
        self.writeresponse('Node "%s" was removed from database!'%params[0])

    @cli_command(28, 'set-config', 'set_config', 'set-conf', validator=(str, str, (str, 0),))
    def command_set_config(self, params):
        '''<config parameter> <parameter value> [<node name>]
        Set configuration of specific node or globally in database
        This command sets configuration of fabnet node (if specified)
        or global configuration
        For runtime applying configuration to started nodes,
        use apply-config command after set new configuration values
        '''
        node_name = None
        if len(params) > 2:
            node_name = params[2]

        self.mgmtManagementAPI.set_config(self.session_id, node_name, {params[0]: params[1]})
        self.writeresponse('Configuration was updated in database!')


    @cli_command(29, 'show-config', 'get_config', 'showconfig', 'sh-conf', validator=((str, 0),))
    def command_show_config(self, params):
        '''[<node name> [--full]]
        Show configuration of specific node or globally
        This command shows configuration of fabnet node (if specified)
        or global configuration
        If --full flag is passed for node's configuration,
        global configuration should be displayed too. 
        '''
        node_name = None
        ret_all = False
        if len(params) > 0:
            node_name = params[0]
            if len(params) > 1:
                if '--full' in params:
                    ret_all = True
                else:
                    raise MEInvalidArgException('Invalid argument "%s"'%params[1])

        config = self.mgmtManagementAPI.get_config(self.session_id, node_name, ret_all)
        self.writeresponse('-'*100)
        self.writeresponse('%-30s %s'%('Parameter name',  'Parameter value'))
        self.writeresponse('-'*100)
        for key, value in config.items():
            if key.startswith('__'): #internal system config parameter
                continue
            self.writeresponse('%-30s %s'%(key,  value))

    @cli_command(30, 'start-node', 'start_nodes', 'startnode', validator=(str,))
    def command_start_node(self, params):
        '''<node name>
        Start node
        This command starts installed fabnet node
        '''
        node_name = params[0]
        resp = self.mgmtManagementAPI.start_nodes(self.session_id, [node_name])
        if resp:
            self.writeresponse(resp)
        else:
            self.writeresponse('Node is started')

    @cli_command(31, 'stop-node', 'stop_nodes', 'stopnode', validator=(str,))
    def command_stop_node(self, params):
        '''<node name>
        Stop node
        This command stops installed fabnet node
        '''
        node_name = params[0]
        resp = self.mgmtManagementAPI.stop_nodes(self.session_id, [node_name])

        if resp:
            self.writeresponse(resp)
        else:
            self.writeresponse('Node is stopped')

    @cli_command(33, 'fabnet-stat', 'get_nodes_stat', 'fabnetstat', 'fstat')
    def command_fabnet_stat(self, params):
        '''
        Show fabnet nodes statistic
        Fields description:
            NODE: fabnet node name
            VERSION: fabnet node version
            NB: neigbours balance <uppers_balance>/<superiors_balance>
            LA: load avarage <5 min>/<10 min>/<15 min>
            OW: fabnet operator workers <all>/<busy>
            OPW: fabnet operations processor workers <all>/<busy>
            FA: fabnet FRI agents <all>/<busy>
            MEMORY: total node memory usage in MB 
        '''
        stats = self.mgmtManagementAPI.get_nodes_stat(self.session_id)

        self.writeresponse('-'*100)
        self.writeresponse('%-15s %s %s %s %s %s %s %s %s'%('NODE',  'VERSION'.center(12), \
                        'NB '.center(6), 'LA '.center(16), 'OW '.center(6), 'OPW'.center(6), \
                        'FA '.center(6), 'MEMORY (MB)'.center(12), 'UPTIME'.center(10) ))
        self.writeresponse('-'*100)

        for node in sorted(stats.keys()):
            n_stat = stats[node]
            s_i = n_stat.get('SystemInfo', {})
            ver = s_i.get('node_version', 'unknown')
            if ver == 'unknown':
                ver = s_i.get('core_version', 'unknown')

            uptime = s_i.get('uptime', '-').split('.')[0]
            la = '%s/%s/%s'%(s_i.get('loadavg_5', '-'), s_i.get('loadavg_10', '-'), s_i.get('loadavg_15', '-'))

            n_i = n_stat.get('NeighboursInfo', {})
            nb = '%s/%s'%(n_i.get('uppers_balance', '-'), n_i.get('superiors_balance', '-'))

            tmp = n_stat.get('OperatorWorkerWMStat', {})
            ow = '%s/%s'%(tmp.get('workers', '-'), tmp.get('busy', '-'))

            tmp = n_stat.get('OperationsProcessorWMStat', {})
            opw = '%s/%s'%(tmp.get('workers', '-'), tmp.get('busy', '-'))

            tmp = n_stat.get('FriAgentWMStat', {})
            fa = '%s/%s'%(tmp.get('workers', '-'), tmp.get('busy', '-'))

            tmp = n_stat.get('OperationsProcessorProcStat', {})
            mem = float(tmp.get('memory', 0))
            tmp = n_stat.get('FriServerProcStat', {})
            mem += float(tmp.get('memory', 0))
            tmp = n_stat.get('OperatorProcStat', {})
            mem += float(tmp.get('memory', 0))
            mem /= 1000 #kB to mB
            mem = '%.2f'%mem

            self.writeresponse('%-15s %s %s %s %s %s %s %s %s'%(node, ver.center(12), \
                        nb.center(6), la.center(16), ow.center(6), opw.center(6), \
                        fa.center(6), mem.center(12), uptime.center(10) ))

    @cli_command(34, 'operations-stat', 'get_nodes_stat', 'opstat', 'ostat')
    def command_operations_stat(self, params):
        '''
        Show fabnet operations statistic
        '''
        stats = self.mgmtManagementAPI.get_nodes_stat(self.session_id)

        self.writeresponse('-'*100)
        self.writeresponse('%-30s %s'%('Operation',  'Process time (ms)'.center(20)))
        self.writeresponse('-'*100)
        operations_stat = {}
        for node, n_stat in stats.items():
            ops = n_stat.get('OperationsProcTime', {})
            for op, o_time in ops.items():
                if not op in operations_stat:
                    operations_stat[op] = [0, 0]
                operations_stat[op][0] += float(o_time)
                operations_stat[op][1] += 1


        for op_name in sorted(operations_stat.keys()):
            o_time, cnt = operations_stat[op_name]
            p_time = '%.1f'%((o_time / cnt)*1000,)
            self.writeresponse('%-30s %s'%(op_name, p_time.center(20)))
             

