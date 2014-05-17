#!/usr/bin/python
"""
Copyright (C) 2012 Konstantin Andrusenko
    See the documentation for further information on copyrights,
    or contact the author. All Rights Reserved.

@package fabnet_mgmt.operator.monitor_operator

@author Konstantin Andrusenko
@date November 11, 2012
"""
import os
import ssl
import time
import threading
import random
import json
import tempfile
import BaseHTTPServer
from datetime import datetime
from Queue import Queue

from fabnet.core.fri_base import  FabnetPacketRequest
from fabnet.core.fri_client import FriClient
from fabnet.core.operator import Operator
from fabnet.core.config import Config
from fabnet.utils.logger import oper_logger as logger
from fabnet.utils.internal import total_seconds
from fabnet.core.constants import ET_ALERT, ET_INFO

from fabnet_mgmt.operator.constants import DEFAULT_MONITOR_CONFIG
from fabnet_mgmt.operator.topology_cognition_mon import TopologyCognitionMon
from fabnet_mgmt.operator.notify_operation_mon import NotifyOperationMon
from fabnet_mgmt.operator.monitor_dbapi import PostgresDBAPI, AbstractDBAPI 
from fabnet_mgmt.engine.mgmt_db import  MgmtDatabaseManager
from fabnet_mgmt.engine.management_engine_api import ManagementEngineAPI
from fabnet_mgmt.engine.constants import STATUS_UP, STATUS_DOWN, \
        DBK_UPPERS, DBK_SUPERIORS, DBK_NODEADDR, DBK_RELEASE_URL, DBK_ID, DBK_UPGRADE_FLAG 
from fabnet_mgmt.cli.base_cli import BaseMgmtCLIHandler
from fabnet_mgmt.rest.rest_service import RESTHandler 

OPERLIST = [NotifyOperationMon, TopologyCognitionMon]

class ManagementOperator(Operator):
    def __init__(self, self_address, home_dir='/tmp/', key_storage=None, is_init_node=False, node_name='unknown', config={}):
        cur_cfg = {}
        cur_cfg.update(DEFAULT_MONITOR_CONFIG)
        cur_cfg.update(config)

        Operator.__init__(self, self_address, home_dir, key_storage, is_init_node, node_name, cur_cfg)

        self.__db_conn_str = None
        self.__db_api = None
        self.check_database()

        if key_storage:
            cert = key_storage.cert()
            ckey = key_storage.cert_key()
        else:
            cert = ckey = None
        client = FriClient(bool(cert), cert, ckey)


        db_conn_str = Config.get('db_conn_str')
        self.__dbm = MgmtDatabaseManager(db_conn_str)
        self.mgmt_api = mgmt_api = ManagementEngineAPI(self.__dbm, self_address)
        BaseMgmtCLIHandler.mgmtManagementAPI = mgmt_api
        host = Config.get('mgmt_cli_host', '0.0.0.0')
        cli_port = int(Config.get('mgmt_cli_port', '23'))
        logger.info('Starting CLI at %s:%s'%(host, cli_port))
        cli_server = TelnetServer((host, cli_port), BaseMgmtCLIHandler)
        #if key_storage:
        #    cert, key = self.get_ssl_keycert('cli_api')
        #    cli_server.socket = ssl.wrap_socket(cli_server.socket, certfile=cert, keyfile=key, server_side=True)
        self.__cli_api_thrd = ExternalAPIThread(cli_server, host, cli_port)
        self.__cli_api_thrd.setName('%s-CLIAPIThread'%self.node_name)
        self.__cli_api_thrd.start()

        RESTHandler.setup_mgmt_api(mgmt_api)
        host = Config.get('mgmt_rest_host', '0.0.0.0')
        rest_port = int(Config.get('mgmt_rest_port', '8080'))
        logger.info('Starting REST at %s:%s'%(host, rest_port))
        rest_server = BaseHTTPServer.HTTPServer((host, rest_port), RESTHandler)
        if key_storage:
            cert, key = self.get_ssl_keycert('rest_api')
            rest_server.socket = ssl.wrap_socket(rest_server.socket, certfile=cert, keyfile=key, server_side=True)
        self.__rest_api_thrd = ExternalAPIThread(rest_server, host, rest_port)
        self.__rest_api_thrd.setName('%s-RESTAPIThread'%self.node_name)
        self.__rest_api_thrd.start()

        if not self.__cli_api_thrd.started():
            self.__rest_api_thrd.stop()
            raise Exception('CLI API does not started!')

        if not self.__rest_api_thrd.started():
            self.__cli_api_thrd.stop()
            raise Exception('CLI API does not started!')

        self.__collect_up_nodes_stat_thread = CollectNodeStatisticsThread(self, client, STATUS_UP)
        self.__collect_up_nodes_stat_thread.setName('%s-UP-CollectNodeStatisticsThread'%self.node_name)
        self.__collect_up_nodes_stat_thread.start()

        self.__collect_dn_nodes_stat_thread = CollectNodeStatisticsThread(self, client, STATUS_DOWN)
        self.__collect_dn_nodes_stat_thread.setName('%s-DN-CollectNodeStatisticsThread'%self.node_name)
        self.__collect_dn_nodes_stat_thread.start()

        self.__discovery_topology_thrd = DiscoverTopologyThread(self)
        self.__discovery_topology_thrd.setName('%s-DiscoverTopologyThread'%self.node_name)
        self.__discovery_topology_thrd.start()

    def get_ssl_keycert(self, context): 
        cert_dir = os.path.join(self.home_dir, 'certs')
        if not os.path.exists(cert_dir):
            os.mkdir(cert_dir)
        cert_file = os.path.join(cert_dir, '%s_cert.pem'%context)
        key_file = os.path.join(cert_dir, '%s_key.pem'%context)
        if os.path.exists(cert_file) and os.path.exists(key_file):
            return cert_file, key_file
        cert, key = self.mgmt_api.generate_ssl_keycert(context)
        open(cert_file, 'w').write(cert)
        open(key_file, 'w').write(key)
        return cert_file, key_file

    def check_database(self):
        db_conn_str = Config.get('db_conn_str')
        if self.__db_api and db_conn_str == self.__db_conn_str:
            return
        
        if self.__db_api:
            try:
                self.__db_api.close()
            except Exception, err:
                logger.error('DBAPI closing failed with error "%s"'%err)

        db_engine = Config.get('db_engine')
        if not db_engine or db_engine == 'mongodb':
            self.__db_api = MgmtDatabaseManager(db_conn_str)
        elif db_engine == 'postgresql':
            self.__db_api = PostgresDBAPI(db_conn_str)
        elif db_engine == 'abstract':
            self.__db_api = AbstractDBAPI()
        else:
            raise Exception('Unknown database engine "%s"!'%db_engine)
        self.__db_conn_str = db_conn_str

    def stop_inherited(self):
        self.__collect_up_nodes_stat_thread.stop()
        self.__collect_dn_nodes_stat_thread.stop()
        self.__discovery_topology_thrd.stop()

        self.__rest_api_thrd.stop()
        self.__cli_api_thrd.stop()
        self.__discovery_topology_thrd.join()
        self.__dbm.close()
        self.__db_api.close()


    def get_nodes_list(self, status=STATUS_UP):
        return self.__db_api.get_nodes_list(status)

    def change_node_status(self, nodeaddr, status):
        self.__db_api.change_node_status(nodeaddr, status)

    def update_node_info(self, nodeaddr, node_name, home_dir, node_type, superior_neighbours, upper_neighbours):
        self.__db_api.update_node_info(nodeaddr, node_name, home_dir, node_type, \
                superior_neighbours, upper_neighbours)

    def update_node_stat(self, nodeaddr, stat):
        self.__db_api.update_node_stat(nodeaddr, stat)

    def notification(self, notify_provider, notify_type, notify_topic, message, date):
        self.__db_api.notification(notify_provider, notify_type, notify_topic, message, date)

    def get_discovered_nodes(self):
        '''
        return nodes in following struct:
            { node_addr:
                { uppers: [addr, ...],
                  superiors: [addr, ...]
                }
            ...
            }
        '''
        ret_nodes = {}
        nodes = self.__db_api.get_fabnet_nodes()
        for node in nodes:
            if not node.has_key(DBK_NODEADDR):
                continue
            node_info = {'uppers': node.get(DBK_UPPERS, []),
                         'superiors': node.get(DBK_SUPERIORS, [])}
            ret_nodes[node[DBK_NODEADDR]] = node_info
        return ret_nodes


class CollectNodeStatisticsThread(threading.Thread):
    def __init__(self, operator, client, check_status=STATUS_UP):
        threading.Thread.__init__(self)
        self.operator = operator
        self.client = client
        self.check_status = check_status
        self.stopped = threading.Event()

    def run(self):
        logger.info('Thread started!')

        while not self.stopped.is_set():
            dt = 0
            try:
                t0 = datetime.now()
                logger.debug('Collecting %s nodes statistic...'%self.check_status)
                nodeaddrs = self.operator.get_nodes_list(self.check_status)

                last_up_node = None
                for nodeaddr in nodeaddrs:
                    logger.debug('Get statistic from %s'%nodeaddr)

                    packet_obj = FabnetPacketRequest(method='NodeStatistic', sync=True)
                    ret_packet = self.client.call_sync(nodeaddr, packet_obj)
                    if self.check_status == STATUS_UP and ret_packet.ret_code:
                        logger.warning('Node with address %s does not response... Details: %s'%(nodeaddr, ret_packet))
                        self.operator.change_node_status(nodeaddr, STATUS_DOWN)
                    elif ret_packet.ret_code == 0:
                        last_up_node = nodeaddr
                        stat = ret_packet.ret_parameters
                        self.operator.update_node_stat(nodeaddr, stat)

                dt = total_seconds(datetime.now() - t0)
                logger.info('Nodes (with status=%s) stat is collected. Processed secs: %s'%(self.check_status, dt))
            except Exception, err:
                logger.error(str(err))
            finally:
                wait_time = int(Config.COLLECT_NODES_STAT_TIMEOUT) - dt
                if wait_time > 0:
                    for i in xrange(int(wait_time)):
                        if self.stopped.is_set():
                            break
                        time.sleep(1)
                    time.sleep(wait_time - int(wait_time))

        logger.info('Thread stopped!')

    def notify(self, nodeaddr, event_type, event_topic, event_message):
        packet_obj = FabnetPacketRequest(method='NotifyOperation', \
                parameters={'event_type':str(event_type), \
                'event_message':str(event_message), 'event_topic': str(event_topic), \
                'event_provider': self.operator.get_self_address()})
        rcode, rmsg = self.client.call(nodeaddr, packet_obj) 
        if rcode:
            logger.error('Can not call NotifyOperation: %s'%rmsg)

    def stop(self):
        self.stopped.set()


class DiscoverTopologyThread(threading.Thread):
    def __init__(self, operator):
        threading.Thread.__init__(self)
        self.operator = operator
        self.stopped = threading.Event()
        self._self_discovery = True
        self._nodes_queue = Queue()

    def run(self):
        logger.info('Thread started!')

        while True:
            try:
                for i in xrange(int(Config.DISCOVERY_TOPOLOGY_TIMEOUT)):
                    if self.stopped.is_set():
                        break
                    time.sleep(1)

                if self.stopped.is_set():
                    break

                self.operator.check_database()

                from_addr = self.next_discovery_node()
                if from_addr:
                    logger.info('Starting topology discovery from %s...'%from_addr)
                    params = {"need_rebalance": 1}
                else:
                    logger.info('Starting topology discovery from this node...')
                    params = {}

                packet = FabnetPacketRequest(method='TopologyCognition', parameters=params)
                self.operator.call_network(packet, from_addr)
            except Exception, err:
                logger.error(str(err))

        logger.info('Thread stopped!')


    def next_discovery_node(self):
        if self._self_discovery:
           from_address = None
        else:
            if self._nodes_queue.empty():
                for nodeaddr in self.operator.get_nodes_list():
                    self._nodes_queue.put(nodeaddr)
            if self._nodes_queue.empty():
                from_address = None
            else:
                from_address = self._nodes_queue.get()

        self._self_discovery = not self._self_discovery
        return from_address


    def stop(self):
        self.stopped.set()



import SocketServer
import socket
class TelnetServer(SocketServer.ThreadingTCPServer):
    allow_reuse_address = True
    timeout = 2

    def handle_error(self, request, client_address):
        """Handle an error gracefully.
        """
        import sys
        tp, _,_ = sys.exc_info()
        if tp == socket.error:
            return
        if tp.__name__ == 'EOFException':
            return
        print '-'*40
        print 'Exception (%s)'%tp,
        print client_address
        import traceback
        traceback.print_exc()
        print '-'*40



class ExternalAPIThread(threading.Thread):
    def __init__(self, server, host, port):
        threading.Thread.__init__(self)
        self.__server = server
        self.is_error = threading.Event()

        self.host = host
        self.port = port

    def run(self):
        logger.info('Thread started!')
        try:
            self.__server.serve_forever()
        except Exception, err:
            self.is_error.set()
            import traceback
            logger.write = logger.info
            traceback.print_exc(file=logger)
            logger.error('Unexpected error: %s'%err)
        logger.info('Thread stopped!')

    def started(self):
        while not self.is_error.is_set():
            time.sleep(.1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect((self.host, int(self.port)))
                return True
            except socket.error:
                pass
            finally:
                sock.close()
        return False
                
    def stop(self):
        if self.__server:
            self.__server.shutdown()
            self.__server.server_close()
        self.join()


ManagementOperator.update_operations_list(OPERLIST)

