
import hashlib

from mgmt_engine.constants import *
from mgmt_engine.exceptions import *
from mgmt_engine.decorators import mgmt_api_method

@mgmt_api_method(ROLE_UM)
def create_user(engine, session_id, username, password, roles):
    if len(password) < 3:
        raise MEInvalidArgException('Password is too short!')

    pwd_hash =  hashlib.sha1(password).hexdigest()
    engine._db_mgr.create_user(username, pwd_hash, roles)

@mgmt_api_method(ROLE_UM)
def get_user_info(engine, session_id, username):
    user = engine._db_mgr.get_user_info(username)
    if not user:
        return user
    session = engine._db_mgr.get_user_last_session(username)
    user[DBK_LAST_SESSION] = session
    return user

@mgmt_api_method(ROLE_UM)
def remove_user(engine, session_id, username):
    user = engine._db_mgr.get_user_info(username)
    if not user:
        raise MENotFoundException('User "%s" does not found!'%username)
    engine._db_mgr.remove_user(username)

@mgmt_api_method(ROLE_UM)
def change_user_roles(engine, session_id, username, roles):
    engine._db_mgr.update_user_info(username, roles=roles)

@mgmt_api_method()
def change_user_password(engine, session_id, username, new_password):
    if username:
        engine.check_roles(session_id, ROLE_UM)
        user = engine._db_mgr.get_user_info(username)
        if not user:
            raise MENotFoundException('User "%s" does not found!'%username)
    else:
        user = engine._db_mgr.get_user_by_session(session_id)
        if user is None:
            raise MEAuthException('Unknown user session!')

    if len(new_password) < 3:
        raise MEInvalidArgException('Password is too short!')

    pwd_hash =  hashlib.sha1(new_password).hexdigest()
    engine._db_mgr.update_user_info(user[DBK_USERNAME], \
            pwd_hash=pwd_hash)

@mgmt_api_method(ROLE_UM)
def get_available_roles(engine, session_id):
    return ROLES_DESC
