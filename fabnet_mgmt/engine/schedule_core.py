import time
import threading
from datetime import datetime, timedelta

from fabnet.utils.logger import init_logger
from fabnet_mgmt.engine.constants import DBK_SCHEDULED_DUMP

logger = init_logger('MGMT-ENGINE', False)

class ScheduledTask(threading.Thread):
    def __init__(self, mgmt_api):
        threading.Thread.__init__(self)
        self.mgmt_api = mgmt_api
        self.setName('Scheduler.%s'%self.__class__.__name__)

    def run(self):
        try:
            self.process()
        except Exception, err:
            logger.error('[Scheduler][%s]: %s'%(self.__class__.__name__, err))

    @classmethod
    def get_wait_time(cls):
        '''Returns time in seconds
        This method must be implemented in inherited class'''
        raise Exception('does not implemented!')

    def process(self):
        '''This method must be implemented in inherited class'''
        raise Exception('does not implemented!')


class ScheduleManager(threading.Thread):
    __TASKS = []
    @classmethod
    def add_task(cls, task):
        if not issubclass(task, ScheduledTask):
            raise Exception('Invalid task class %s!'%task)
        if task in cls.__TASKS:
            return
        cls.__TASKS.append(task)

    def __init__(self, mgmt_api):
        threading.Thread.__init__(self)
        self.__stop_flag = threading.Event()
        self.setName('ScheduleManager')
        self.mgmt_api = mgmt_api
        self.scheduled = []

    def run(self):
        self.__init()
        while not self.__stop_flag.is_set():
            wait_secs = 1
            try:
                wait_secs = self.__proc()
                ms = wait_secs - int(wait_secs)
                time.sleep(ms)
                logger.info('Waiting %s seconds...'%int(wait_secs))
            except Exception, err:
                logger.error('error: %s'% err)
            finally:
                for _ in xrange(int(wait_secs)):
                    if self.__stop_flag.is_set():
                        break
                    time.sleep(1.0)

        self.__save()

    def __init(self):
        scheduled = self.mgmt_api.get_config_var(DBK_SCHEDULED_DUMP)
        sch_map = {}
        if scheduled:
            for dt, task in scheduled:
                sch_map[task] = dt
            
        now = datetime.now()
        for task in self.__TASKS:
            dt = sch_map.get(task.__name__, None)
            if dt:
                self.scheduled.append((dt, task))
            else:
                secs = task.get_wait_time()
                self.scheduled.append((now + timedelta(0, secs), task))  
        self.scheduled.sort(key=lambda item: item[0])

    def __save(self):
        d_list = []
        for s_time, task in self.scheduled:
            d_list.append((s_time, task.__name__))

        self.mgmt_api.update_config({DBK_SCHEDULED_DUMP: d_list})
        logger.info('Dump scheduled tasks to database')

    def stop(self):
        self.__stop_flag.set()
        self.join()

    def __proc(self):
        now = datetime.now()
        if not self.scheduled:
            return 10

        pop_cnt = 0
        for s_time, task in self.scheduled:
            if s_time < now:
                task(self.mgmt_api).start()
                pop_cnt += 1
            else:
                break

        for i in xrange(pop_cnt):
            s_time, task = self.scheduled.pop(0) 
            secs = task.get_wait_time()
            self.scheduled.append((now + timedelta(0, secs), task))

        self.scheduled.sort(key=lambda item: item[0])
        return (self.scheduled[0][0] - now).total_seconds()

