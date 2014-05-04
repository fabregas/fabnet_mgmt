import os
import sys
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

if __name__ == '__main__':
    setup(
        name = "fabnet-mgmt",
        version = read('VERSION'),
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
