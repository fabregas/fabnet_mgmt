
import hashlib

from fabnet_mgmt.engine.constants import ROLE_UM, DBK_LAST_SESSION, \
                DBK_USERNAME, ROLES_DESC
from fabnet_mgmt.engine.exceptions import MEInvalidArgException, \
        MENotFoundException, MEAuthException 
from fabnet_mgmt.engine.decorators import MgmtApiMethod

@MgmtApiMethod(ROLE_UM)
def create_user(engine, session_id, username, password, roles):
    if len(password) < 3:
        raise MEInvalidArgException('Password is too short!')

    pwd_hash =  hashlib.sha1(password).hexdigest()
    engine.db_mgr().create_user(username, pwd_hash, roles)

@MgmtApiMethod(ROLE_UM)
def get_user_info(engine, session_id, username):
    user = engine.db_mgr().get_user_info(username)
    if not user:
        return user
    session = engine.db_mgr().get_user_last_session(username)
    user[DBK_LAST_SESSION] = session
    return user

@MgmtApiMethod(ROLE_UM)
def remove_user(engine, session_id, username):
    user = engine.db_mgr().get_user_info(username)
    if not user:
        raise MENotFoundException('User "%s" does not found!'%username)
    engine.db_mgr().remove_user(username)

@MgmtApiMethod(ROLE_UM)
def change_user_roles(engine, session_id, username, roles):
    engine.db_mgr().update_user_info(username, roles=roles)

@MgmtApiMethod()
def change_user_password(engine, session_id, username, new_password):
    if username:
        engine.check_roles(session_id, ROLE_UM)
        user = engine.db_mgr().get_user_info(username)
        if not user:
            raise MENotFoundException('User "%s" does not found!'%username)
    else:
        user = engine.db_mgr().get_user_by_session(session_id)
        if user is None:
            raise MEAuthException('Unknown user session!')

    if len(new_password) < 3:
        raise MEInvalidArgException('Password is too short!')

    pwd_hash =  hashlib.sha1(new_password).hexdigest()
    engine.db_mgr().update_user_info(user[DBK_USERNAME], \
            pwd_hash=pwd_hash)

@MgmtApiMethod(ROLE_UM)
def get_available_roles(engine, session_id):
    return ROLES_DESC

