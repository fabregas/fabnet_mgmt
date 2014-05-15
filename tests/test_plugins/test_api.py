

from fabnet_mgmt.engine.decorators import MgmtApiMethod
from fabnet_mgmt.engine.constants import ROLE_RO

@MgmtApiMethod(ROLE_RO)
def test_api_method(engine, session_id, data):
    engine.db_mgr().get_config(None)
    return data


