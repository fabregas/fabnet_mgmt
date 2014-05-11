import json
import socket
import base64
import urllib
from httplib import HTTPConnection, HTTPSConnection

class RESTException(Exception):
    pass

class RestAPI(object):
    def __init__(self, url, username, password, timeout=10):
        parts = url.split('/')
        service = parts[0]
        self.__host = parts[2]
        self.__timeout = timeout
        auth = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
        self.__headers = {"Authorization": "Basic %s" % auth}

        self.__conn_class = HTTPSConnection if service == 'https:' else HTTPConnection
        self.__methods = self.__call('GET', '')

    def __call(self, http_method, method, *args, **kvargs):
        conn = None
        try:
            conn = self.__conn_class(self.__host, timeout=self.__timeout)

            if args:
                kvargs['__args'] = args
            params = json.dumps(kvargs)
    
            conn.request(http_method, '/%s'%method, params, self.__headers)
            resp = conn.getresponse()
            if resp.status != 200:
                raise RESTException('REST error [%s] %s'%(resp.status, resp.reason))
            data = resp.read()
            try:
                data = json.loads(data)
            except Exception, err:
                raise RESTException('Invalid JSON data "%s"'%data)
        except socket.error, err:
            raise RESTException('Remote host %s error: %s'%(self.__host, err))
        finally:
            if conn:
                conn.close()
        return data

    def __caller(self, http_method, method_name):
        def method(*args, **kvargs):
            return self.__call(http_method, method_name, *args, **kvargs)
        return method

    def __getattr__(self, attr):
        for http_method, methods in self.__methods.items():
            if attr in methods:
                return self.__caller(http_method, attr)
        raise RESTException('Unknown method "%s"!'%attr)
        
