#!/usr/bin/python
"""
Copyright (C) 2014 Konstantin Andrusenko
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.

@package fabnet.mgmt.management_engine_api
@author Konstantin Andrusenko
@date January 31, 2014
"""

class mgmt_api_method:
    '''
    decorator class for automatic API methods discovery
    and authentication
    '''
    roles_map = {}
    methods = {}
    mgmt_engine_api = None

    def __init__(self, *roles):
        self.roles = roles

    def __call__(self, method):
        '''
        update global roles and methods dicts
        and decorate API method for auth
        '''
        self.roles_map[method.__name__] = self.roles
        def decorated(session_id, *args, **kw_args):
            '''decorated method with check roles call'''
            if not self.mgmt_engine_api:
                raise Exception('mgmt_api_method class should be '\
                        'initialized by ManagementEngineAPI instance')
            if self.roles:
                self.mgmt_engine_api.check_roles(session_id, self.roles)
            return method(self.mgmt_engine_api, session_id, *args, **kw_args)
        self.methods[method.__name__] = decorated
        return decorated
