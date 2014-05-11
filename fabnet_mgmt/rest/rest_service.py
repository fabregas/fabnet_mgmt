import re
import base64
import json
import datetime
import BaseHTTPServer

def requires_auth(f):
    def decorated(*args, **kwargs):        
        web = args[0]
        if web.session_id is not None:
            return f(*args, **kwargs)

        auth = web.headers.getheader('Authorization')
        if auth:
            auth = re.sub('^Basic ', '', auth)
            username, password = base64.decodestring(auth).split(':')

        if auth:
            try:
                web.session_id = RESTHandler.check_auth(username, password)
            except Exception, err:
                return web.send_error(401, str(err))

            resp = f(*args, **kwargs)
            RESTHandler.logout(web.session_id)
            return resp

        #web.send_error(401)
        web.do_HEAD()

    return decorated

def default_json_dump(o):
    if type(o) is datetime.date or type(o) is datetime.datetime:
        return o.isoformat()

class RESTHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    __mgmt_api = None

    METHODS_MAP = {
            'GET': {'getUserInfo': 'get_user_info', \
                    'getAvailableRoles': 'get_available_roles', \
                    'getNodes': 'show_nodes',\
                    'getSSHKey': 'get_ssh_key', \
                    'getReleases': 'get_releases', \
                    'getConfig': 'get_config', \
                    'getNodesStat': 'get_nodes_stat'
                    }, 
            'POST': {'createUser': 'create_user', \
                    'installPhysicalNode': 'install_physical_node', \
                    'installFabnetNode': 'install_fabnet_node', \
                    'setRelease': 'set_release', \
                    'setConfig': 'set_config', \
                    'applyConfig': 'apply_config', \
                    'initKeyStorage': 'init_session_key_storage'
                    },
            'PATCH': {'changeUserRoles': 'change_user_roles', \
                    'changeUserPassword': 'change_user_password',\
                    'startNodes': 'start_nodes', \
                    'stopNodes': 'stop_nodes', \
                    'reloadNodes': 'reload_nodes', \
                    'upgradeNodes': 'upgrade_nodes'
                    },
            'DELETE': {'removeUser': 'remove_user', \
                    'removePhysicalNode': 'remove_physical_node', \
                    'removeFabnetNode': 'remove_fabnet_node'
                    },
            }
    
    @classmethod
    def setup_mgmt_api(cls, mgmt_api):
        cls.__mgmt_api = mgmt_api

    @classmethod
    def check_auth(cls, username, password):
        return cls.__mgmt_api.authenticate(username, password)

    @classmethod
    def logout(cls, session_id):
        return cls.__mgmt_api.logout(session_id)

    def __init__(self, *args, **kvargs):
        self.session_id = None
        BaseHTTPServer.BaseHTTPRequestHandler.__init__(self, *args, **kvargs)

    def do_HEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="admin"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def return_help(self):
        methods = {}
        for h_method, mm in self.METHODS_MAP.items():
            methods[h_method] = mm.keys()
        resp = json.dumps(methods, indent=4, sort_keys=True)
        resp += '\n'

        self.send_response(200)
        self.send_header('Content-length', len(resp))
        self.send_header("Content-type", "application/json")
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(resp)

    def __proc_method(self, http_method):
        try:
            path = self.path
            if path.startswith('/'):
                path = path[1:]
            if path.endswith('/'):
                path = path[:-1]

            if not path:
                return self.return_help()

            parts = path.split('/')
            method_name = parts[0]
 
            length = int(self.headers.get('content-length', 0))
            if length:
                data = self.rfile.read(length)
                try:
                    kv_args = json.loads(data)
                except Exception, err:
                    raise Exception('Invalid JSON data "%s"!'%data)
            else:
                kv_args = {}

            argv = []
            for key, value in kv_args.items():
                if type(value) == unicode:
                    kv_args[key] = value.encode('utf8')

                if key == '__args':
                    for item in value:
                        if type(item) == unicode:
                            item = item.encode('utf8')
                        #if item.lower() == 'none':
                        #    item = None
                        argv.append(item)

            if '__args' in kv_args:
                del kv_args['__args']

            methods = self.METHODS_MAP.get(http_method, None)
            if methods is None:
                raise Exception('No methods for %s found!'%http_method)

            method = methods.get(method_name, None)
            if method is None:
                raise Exception('Unknown method "%s"!'%method_name)

            #print('Processing REST method %s. argv=%s, kvargs=%s' \
            #       %(method_name, str(argv), str(kv_args)))

            api_method = getattr(self.__mgmt_api, method, None)
            if api_method is None:
                raise Exception('Unknown API method "%s"!'%method)
            resp = api_method(self.session_id, *argv, **kv_args)
            #print ('Response: %s'%str(resp))

            try:
                resp = json.dumps(resp, default=default_json_dump, indent=4, sort_keys=True)
                resp += '\n'
            except Exception, err:
                raise Exception('Can not dump response! Details: %s'%err)

            self.send_response(200)
            self.send_header('Content-length', len(resp))
            self.send_header("Content-type", "application/json")
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(resp)
        except Exception, err:
            self.send_error(500, str(err))


    @requires_auth
    def do_GET(self):
        self.__proc_method('GET')

    @requires_auth
    def do_POST(self):
        self.__proc_method('POST')

    @requires_auth
    def do_PATCH(self):
        self.__proc_method('PATCH')

    @requires_auth
    def do_DELETE(self):
        self.__proc_method('DELETE')


