
from fabnet_mgmt.cli.decorators import cli_command

@cli_command(50, 'test-plugin-operation', 'test_api_method', 'testplugins', validator=(str,))
def command_operations_stat(cli, params):
    '''<message>
    Echo operation
    '''
    ret = cli.mgmtManagementAPI.test_api_method(cli.session_id, params[0])
    cli.writeresponse('RESPONSE: %s'%ret)
