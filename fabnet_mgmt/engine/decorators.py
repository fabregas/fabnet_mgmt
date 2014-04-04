#!/usr/bin/python
"""
Copyright (C) 2014 Konstantin Andrusenko
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.

@package fabnet.mgmt.management_engine_api
@author Konstantin Andrusenko
@date January 31, 2014
"""

class MgmtApiMethod:
    '''
    decorator class for automatic API methods discovery
    and authentication
    '''
    __roles_map = {}
    __methods = {}
    __mgmt_engine_api = None

    def __init__(self, *roles):
        self.__roles = roles

    def __call__(self, method):
        '''
        update global roles and methods dicts
        and decorate API method for auth
        '''
        self.__roles_map[method.__name__] = self.__roles
        def decorated(session_id, *args, **kw_args):
            '''decorated method with check roles call'''
            if not self.__mgmt_engine_api:
                raise Exception('mgmt_api_method class should be '\
                        'initialized by ManagementEngineAPI instance')
            if self.__roles:
                self.__mgmt_engine_api.check_roles(session_id, self.__roles)
            return method(self.__mgmt_engine_api, session_id, *args, **kw_args)
        self.__methods[method.__name__] = decorated
        return decorated

    @classmethod
    def set_mgmt_engine_api(cls, engine):
        '''install instance of management engine API'''
        cls.__mgmt_engine_api = engine

    @classmethod
    def iter_roles(cls):
        '''get list of (method_name, roles)'''
        return cls.__roles_map.items()

    @classmethod
    def get_method(cls, method_name):
        '''get method instance by name'''
        return cls.__methods.get(method_name, None)

