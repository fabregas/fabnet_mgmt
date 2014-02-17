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

class ThrowingArgumentParser(argparse.ArgumentParser):
    def error(self, message):
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
    def command_install_phy_node(self, params):
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

