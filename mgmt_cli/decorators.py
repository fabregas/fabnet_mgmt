#!/usr/bin/python
"""
Copyright (C) 2014 Konstantin Andrusenko
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.

@package mgmt_cli.decorators
@author Konstantin Andrusenko
@date January 31, 2014
"""

from mgmt_engine import exceptions

class InvalidArgException(Exception):
    pass

class cli_command:
    cli_commands = {}

    def __init__(self, num, cmd_name, api_method_name=None, *aliases, **kw_args):
        self.cmd_name = cmd_name
        self.api_method_name = api_method_name
        self.aliases = aliases
        self.num = num
        self.val_expr_list = kw_args.get('validator', [])
        self.doc = ''

    def __call__(self, method):
        def validate_and_call(self_m, params, *others):
            try:
                try:
                    self.__validate_args(params) 
                except InvalidArgException, err:
                    doc = self.doc.split("\n")
                    docp = doc[0].strip()
                    self_m.writeresponse("Usage: %s %s"%(self.cmd_name.upper(), docp))
                    return

                return method(self_m, params, *others)
            except exceptions.MEBaseException, err:
                self_m.writeresponse('Error! %s\n'%err)
            except Exception, err:
                #import traceback
                #traceback.print_exc(file=self_m)
                self_m.writeresponse('Unexpected error: %s\n'%err)


        self.doc = method.__doc__
        self.cli_commands[self.cmd_name] = (validate_and_call, self.api_method_name, \
                self.aliases, self.doc, self.num)

        return method


    def __validate_args(self, params):
        def validate(val, v_type):
            if not isinstance(val, v_type):
                raise InvalidArgException(val)
        i = 0
        for validator in self.val_expr_list:
            if type(validator) == tuple:
                p_c_type = validator[0]
                min_cnt = validator[1]

                while True:
                    if min_cnt > 0 and len(params) < i+1:
                        raise InvalidArgException()
                    if len(params) < i+1:
                        break
                    validate(params[i], p_c_type)
                    i += 1
                    min_cnt -= 1
            else:
                if len(params) < i+1:
                    raise InvalidArgException()
                validate(params[i], validator)
                i += 1

