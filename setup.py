import os
import sys
from setuptools import setup
from setup_routines import *

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

if __name__ == '__main__':
    prepare_install('/opt/blik/fabnet', '/opt/blik/fabnet/mgmt_package_files.lst')

    setup(
        name = "fabnet-mgmt",
        version = get_cur_ver(),
        author = "Fabregas",
        author_email = "kksstt@gmail.com",
        description = ("Management core for fabnet network."),
        license = "CC BY-NC",
        url = "https://github.com/fabregas/fabnet_mgmt/wiki",
        packages=['fabnet_mgmt', 'fabnet_ca'],
        data_files=[('', ['VERSION'])],        
        scripts=get_all('./bin'),
        long_description=read('README'),
    )

    try:
        install_submodule('https://github.com/fabregas/fabnet/archive/master.zip', 'fabnet_package_files.lst')

        check_deps({GENTOO: ('pymongo', 'openssl', 'paramiko', 'cherrypy'), \
                RHEL: ('openssl', 'python-paramiko', 'python-cherrypy'), \
                DEBIAN: ('openssl', 'python-crypto', 'python-cherrypy')})
    except Exception, err:
        print (err)
        sys.exit(1)

    setup_user()
    update_user_profile()
