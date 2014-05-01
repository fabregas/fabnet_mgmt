import unittest
import sys
import time
import os
import logging
import shutil
import threading
import json
import random
import string
import hashlib
import subprocess
import signal

from pymongo import MongoClient

sys.path.append('fabnet_core')

from fabnet.core.config import Config
from fabnet.core.fri_base import FabnetPacketRequest, FabnetPacketResponse
from fabnet.core.fri_client import FriClient
from fabnet.core.constants import RC_OK, NT_SUPERIOR, NT_UPPER, ET_INFO, ET_ALERT
from fabnet_mgmt.engine.mgmt_db import MgmtDatabaseManager
from fabnet_mgmt.engine.management_engine_api import ManagementEngineAPI
from fabnet.core.key_storage import init_keystore

from fabnet.utils.logger import logger

from fabnet_mgmt.engine.constants import *

import pexpect

logger.setLevel(logging.DEBUG)

PROCESSES = []
ADDRESSES = []
DEBUG = False

MONITOR_DB = 'test_fabnet_monitor_db'
CA_DB = 'test_ca_db'

KS_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), '../fabnet_core/tests/cert/test_keystorage.p12')
KS_PATH_2 = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'ks/test.p12')
KS_PASSWD = 'node'


class TestMonitorNode(unittest.TestCase):
    def create_net(self, nodes_count):
        global PROCESSES
        global ADDRESSES

        for unuse in range(nodes_count):
            if not ADDRESSES:
                n_node = 'init-fabnet'
                i = 1900
            else:
                n_node = random.choice(ADDRESSES)
                i = int(ADDRESSES[-1].split(':')[-1])+1
                self._wait_node(n_node)

            address = '127.0.0.1:%s'%i
            ADDRESSES.append(address)

            home = '/tmp/node_%s'%i
            if os.path.exists(home):
                shutil.rmtree(home)
            os.mkdir(home)
            os.system('cp fabnet_core/tests/cert/test_certs.ca %s/'%home)

            logger.warning('{SNP} STARTING NODE %s'%address)
            if n_node == 'init-fabnet':
                ntype = 'Monitor'
                Config.load(os.path.join(home, 'fabnet.conf'))
                Config.update_config({'db_engine': 'mongodb', \
                        'db_conn_str': "mongodb://127.0.0.1/%s"%MONITOR_DB,\
                        'COLLECT_NODES_STAT_TIMEOUT': 1,
                        'mgmt_cli_port': 2323})
            else:
                ntype = 'Base'
            args = ['/usr/bin/python', './fabnet_core/fabnet/bin/fabnet-node', address, n_node, 'NODE%.02i'%i, home, ntype, \
                    KS_PATH, '--input-pwd', '--nodaemon']
            if DEBUG:
                args.append('--debug')
            print ' '.join(args)
            p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,\
                    env={'FABNET_PLUGINS_CONF': 'tests/plugins.yaml', 'PYTHONPATH': os.path.abspath('.')})
            p.stdin.write(KS_PASSWD+'\n')
            logger.warning('{SNP} PROCESS STARTED')
            time.sleep(1)

            PROCESSES.append(p)
            #if len(ADDRESSES) > 2:
            #    self._check_stat(address)

        for address in ADDRESSES:
            self._check_stat(address)

        time.sleep(1.5)
        print 'NETWORK STARTED'

    def _wait_node(self, node):
        idx = None
        for i, addr in enumerate(ADDRESSES):
            if addr == node:
                idx = i
        if idx is None:
            raise Exception('address %s does not found!'%node)

        proc = PROCESSES[idx]

        key_storage = init_keystore(KS_PATH, KS_PASSWD)
        cert = key_storage.cert()
        ckey = key_storage.cert_key()
        client = FriClient(True, cert, ckey)
        while True:
            if not os.path.exists('/proc/%s'%proc.pid):
                raise Exception('Node process for %s does not found!')
            for line in open("/proc/%d/status" % proc.pid).readlines():
                if line.startswith("State:"):
                    status = line.split(":",1)[1].strip().split(' ')[0]
            if status == 'Z':
                raise Exception('Node died at %s'%node)

            packet_obj = FabnetPacketRequest(method='NodeStatistic', sync=True)
            ret_packet = client.call_sync(node, packet_obj)
            if ret_packet.ret_code:
                print ret_packet.ret_message
                print 'Node does not init FRI server yet. Waiting it...'
                time.sleep(.5)
                continue
            break

    def _check_stat(self, address):
        key_storage = init_keystore(KS_PATH, KS_PASSWD)
        cert = key_storage.cert()
        ckey = key_storage.cert_key()
        client = FriClient(True, cert, ckey)

        while True:
            try:
                packet_obj = FabnetPacketRequest(method='NodeStatistic', sync=True)
                ret_packet = client.call_sync(address, packet_obj)
                if ret_packet.ret_code:
                    time.sleep(.5)
                    continue

                uppers_balance = int(ret_packet.ret_parameters['NeighboursInfo'][u'uppers_balance'])
                superiors_balance = int(ret_packet.ret_parameters['NeighboursInfo'][u'superiors_balance'])
                if uppers_balance >= 0 and superiors_balance >= 0:
                    return
                else:
                    print 'Node %s is not balanced yet! Waiting...'%address
                time.sleep(.5)
            except Exception, err:
                logger.error('ERROR: %s'%err)
                raise err

    def test00_initnet(self):
        for db in [CA_DB, MONITOR_DB]:
            client = MongoClient("mongodb://127.0.0.1/%s"%db)
            db_c = client.get_default_database()
            client.drop_database(db_c)

        mgmt_db = client.get_default_database()
        CNT = 4
        for i in xrange(CNT):
            mgmt_db[DBK_NODES].insert({DBK_ID: 'NODE%.02i'%(1900+i)})

        dbm = MgmtDatabaseManager("mongodb://127.0.0.1/%s"%MONITOR_DB)
        ManagementEngineAPI.initial_configuration(dbm, 'test_cluster', True, 'mongodb://127.0.0.1/%s'%CA_DB)

        self.create_net(CNT)

    def test01_monitor(self):
        client = MongoClient("mongodb://127.0.0.1/%s"%MONITOR_DB)
        mgmt_db = client.get_default_database()

        events = mgmt_db[DBK_NOTIFICATIONS].find({DBK_NOTIFY_TOPIC: 'NodeUp'})
        self.assertEqual(events.count(), 3)

        #p = subprocess.Popen(['/usr/bin/python', './fabnet_core/fabnet/bin/fri-caller', 'TopologyCognition', ADDRESSES[0], '{}', 'async'])
        key_storage = init_keystore(KS_PATH, KS_PASSWD)
        cert = key_storage.cert()
        ckey = key_storage.cert_key()
        client = FriClient(True, cert, ckey)
        packet_obj = FabnetPacketRequest(method='TopologyCognition')
        ret_code, msg = client.call(ADDRESSES[0], packet_obj)
        self.assertEqual(ret_code, 0, msg)
        time.sleep(2)

        nodes_info = mgmt_db[DBK_NODES].find({})
        self.assertEqual(nodes_info.count(), 4)

        #for node in nodes_info:
        #    print node

        node_info = mgmt_db[DBK_NODES].find_one({DBK_NODEADDR: ADDRESSES[0]})
        self.assertEqual(node_info[DBK_NODEADDR], ADDRESSES[0])
        self.assertEqual(node_info[DBK_ID], 'NODE1900')
        self.assertTrue(node_info[DBK_STATUS]==1)
        self.assertTrue(len(node_info[DBK_UPPERS]) >= 2)
        self.assertTrue(node_info[DBK_SUPERIORS] >= 2)
        self.assertTrue(float(node_info[DBK_STATISTIC]['SystemInfo']['loadavg_10']) > 0)

    def test02_check_cli(self):
        cli = pexpect.spawn('telnet 127.0.0.1 2323', timeout=2)
        cli.logfile_read = sys.stdout
        try:
            cli.expect('Username:')
            cli.sendline('admin')
            cli.expect('Password:')
            cli.sendline('admin')
            cli.expect('mgmt-cli>')
            cli.sendline('exit')
            cli.expect(pexpect.EOF)
        finally:
            cli.close(force=True)

    def test09_stopnet(self):
        for process in PROCESSES:
            process.send_signal(signal.SIGINT)
        print 'SENDED SIGNALS'
        for process in PROCESSES:
            process.wait()
        print 'STOPPED'

    def test10_start_with_annother_ks(self): 
        address = '127.0.0.1:1991'
        ADDRESSES.append(address)

        home = '/tmp/node_monitor_new'
        if os.path.exists(home):
            shutil.rmtree(home)
        os.mkdir(home)
        logger.warning('{SNP} STARTING NODE %s'%address)

        Config.load(os.path.join(home, 'fabnet.conf'))
        Config.update_config({'db_engine': 'mongodb', \
                'db_conn_str': "mongodb://127.0.0.1/%s"%MONITOR_DB,\
                'COLLECT_NODES_STAT_TIMEOUT': 1,
                'mgmt_cli_port': 2323})

        args = ['/usr/bin/python', './fabnet_core/fabnet/bin/fabnet-node', address, 'init-fabnet', 'NODEMON', home, 'Monitor', \
                KS_PATH_2, '--input-pwd', '--nodaemon']
        if DEBUG:
            args.append('--debug')
        print ' '.join(args)
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,\
                env={'FABNET_PLUGINS_CONF': 'tests/plugins.yaml', 'PYTHONPATH': os.path.abspath('.')})
        p.stdin.write(KS_PASSWD+'\n')
        out, err = p.communicate()
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue('SSHException:' in err, err)

if __name__ == '__main__':
    unittest.main()

