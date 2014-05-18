
from fabnet_mgmt.engine.schedule_core import ScheduledTask
from fabnet.utils.logger import logger
from fabnet.core.config import Config

class ChangeAuthKeyTask(ScheduledTask):
    @classmethod
    def get_wait_time(cls):
        return int(Config.get('AUTH_KEY_CHANGE_PERIOD', 43200))

    def process(self):
        logger.info('Updating AuthKey for fabnet network...')
        rcode, rmsg = self.mgmt_api.fri_call_net(None, 'ChangeAuthKey')
        if rcode:
            logger.error('ChangeAuthKey call failed: %s'%rmsg)
