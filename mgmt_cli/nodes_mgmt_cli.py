#!/usr/bin/python
"""
Copyright (C) 2014 Konstantin Andrusenko
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.

@package mgmt_cli.nodes_mgmt_cli
@author Konstantin Andrusenko
@date February 3, 2014
"""

from mgmt_cli.decorators import cli_command
from mgmt_engine.constants import *
from mgmt_engine.exceptions import MENotFoundException, MEInvalidArgException

import os
import urllib2
import tempfile
import argparse

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
    @cli_command(20, 'install-physical-node', 'install_physical_node', 'intalpnode', 'i-pnode', validator=(str, str, str))
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

    @cli_command(21, 'show-nodes', 'show_nodes', 'shnodes', 'shownodes')
    def command_install_phy_node(self, params):
        '''[--physical|-p] [--type|-t <node type>]
        Show information about configured nodes
        This command shows information about physical and logical nodes
        that installed in the system
        '''
        parser = argparse.ArgumentParser()
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
        if args.is_phys:
            self.writeresponse('%-20s %s %s %s'%('HOSTNAME',  \
                        'MEMORY (Gb)'.center(15), 'CORES'.center(5), 'CPU MODEL'.center(60)))
            self.writeresponse('-'*100)
            for node in nodes:
                self.writeresponse('%-20s %s %s %s'%(node[DBK_ID], \
                        #node[DBK_INSTALLDATE].strftime('%d.%m.%Y %H:%M').center(20),\
                        ('%.2f'%node[DBK_MEMORY]).center(15),\
                        str(node[DBK_CORESCNT]).center(5),\
                        str(node[DBK_CPUMODEL]).center(60)))

