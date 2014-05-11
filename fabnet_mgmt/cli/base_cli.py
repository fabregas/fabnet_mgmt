#!/usr/bin/python
"""
Copyright (C) 2013 Konstantin Andrusenko
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.

@package fabnet.mgmt.management_agent
@author Konstantin Andrusenko
@date July 27, 2013

This module contains the implementation of BaseMgmtCLIHandler class
and decorators for easy CLI commands implement
"""

from fabnet_mgmt.cli.decorators import *
from fabnet_mgmt.cli.telnetserver.threaded import TelnetHandler
from fabnet_mgmt.cli.users_mgmt_cli import * 
from fabnet_mgmt.cli.nodes_mgmt_cli import * 

class BaseMgmtCLIHandler(TelnetHandler):
    PROMPT = 'mgmt-cli> '
    WELCOME = '%s\n%s\n%s'%('='*80, '  Welcome to fabnet management console  '.center(80, '='), '='*80)

    authNeedUser = True
    authNeedPass = True

    mgmtManagementAPI = None

    def authCallback(self, username, password):
        if not self.mgmtManagementAPI:
            return

        try:
            self.session_id = self.mgmtManagementAPI.authenticate(username, password)
        except Exception, err:
            self.writeresponse('ERROR! %s'%err)
            raise err

        if self.mgmtManagementAPI.need_key_storage_init():
            pwd = self.readline(prompt='Please, enter management key storage password: ', echo=False)
            self.writeline('')
            try:
                self.mgmtManagementAPI.init_key_storage(pwd)
            except Exception, err:
                self.writeresponse('ERROR! %s'%err)
                raise err

        try:
            cli_hist = self.mgmtManagementAPI.get_session_data(self.session_id, 'cli_history')
            if cli_hist and type(cli_hist) == list:
                self.history = [str(cmd) for cmd in cli_hist]
        except Exception, err:
            self.writeresponse('ERROR! %s'%err)

    def session_start(self):
        self.COMMANDS = {}
        self.ordered_commands = []
        allowed_methods = self.mgmtManagementAPI.get_allowed_methods(self.session_id)
        prev_num = None
        for name, (method, api_method, aliases, _, num) in sorted(cli_command.cli_commands.items(), cmp=lambda a,b: cmp(a[1][4],b[1][4])):
            if api_method and api_method not in allowed_methods:
                continue
            name = name.upper()
            def decorate(method):
                def decorated(*args, **kw_args):
                    return method(self, *args, **kw_args)
                return decorated

            self.COMMANDS[name] = decorate(method)
            if prev_num and (num - prev_num) > 1:
                self.ordered_commands.append('')
            prev_num = num
            self.ordered_commands.append(name)
            for alias in aliases:
                self.COMMANDS[alias.upper()] = self.COMMANDS[name]

    def session_end(self):
        if getattr(self, 'session_id', None) is None:
            return
        if self.history:
            self.mgmtManagementAPI.set_session_data(self.session_id, 'cli_history', self.history[:100])
        self.mgmtManagementAPI.logout(self.session_id)

    @cli_command(0, 'help')
    def command_help(self, params):
        """[<command>]
        Display help information
        Display either brief help on all commands, or detailed
        help on a single command passed as a parameter.
        """
        if params:
            cmd = params[0].upper()

            method = cli_command.cli_commands.get(cmd.lower(), None)
            if method:
                _, _, aliases, help_msg, num = method
                doc = help_msg.split("\n")
                docp = doc[0].strip()
                docl = '\n'.join( [l.strip() for l in doc[2:]] )
                if not docl.strip():  # If there isn't anything here, use line 1
                    docl = doc[1].strip()
                if aliases:
                    al_doc = '\nCommand aliases: %s'%', '.join(aliases)
                else:
                    al_doc = ''
                self.writeline("%s %s\n\n%s%s" % (cmd, docp, docl, al_doc))
                return
            else:
                self.writeline("Command '%s' not known" % cmd)
                self.writeline("")

        self.writeline("Help on built in commands\n")

        for cmd in self.ordered_commands:
            if not cmd:
                self.writeline("")
                continue
            method = cli_command.cli_commands.get(cmd.lower(), None)
            if not method:
                continue
            _, _, aliases, help_msg, num = method

            doc = help_msg.split("\n")
            docp = doc[0].strip()
            docs = doc[1].strip()
            #if len(docp) > 0:
            #    docps = "%s - %s" % (docp, docs, )
            #else:
            #    docps = "- %s" % (docs, )
            self.writeline("%s - %s" % (cmd.ljust(20), docs))

    @cli_command(1, 'exit')
    def command_exit(self, params):
        """
        Exit the command shell
        """
        self.RUNSHELL = False
        self.writeline("Goodbye")
