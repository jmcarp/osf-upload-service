# encoding: utf-8

import re
from setuptools import setup, find_packages


REQUIRES = [

    # Storage backends
    'boto==2.32.1',
    'pyrax==1.9.2',

    # Miscellaneous
    'furl==0.3.95',
    'python-dateutil==2.2',
    'requests==2.4.1',
    'six==1.8.0',
    'werkzeug==0.9.6',

]


def find_version(fname):
    '''Attempts to find the version number in the file names fname.
    Raises RuntimeError if not found.
    '''
    version = ''
    with open(fname, 'r') as fp:
        reg = re.compile(r'__version__ = [\'"]([^\'"]*)[\'"]')
        for line in fp:
            m = reg.match(line)
            if m:
                version = m.group(1)
                break
    if not version:
        raise RuntimeError('Cannot find version information')
    return version


def read(fname):
    with open(fname) as fp:
        content = fp.read()
    return content


setup(
    name='cloudstorm',
    description='OSF Upload Service',
    author='Center for Open Science',
    author_email='josh@cos.io',
    url='https://github.com/CenterForOpenScience/osf-upload-service',
    packages=find_packages(exclude=("tests*", )),
    package_dir={'cloudstorm': 'cloudstorm'},
    include_package_data=True,
    install_requires=REQUIRES,
    zip_safe=False,
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
    ],
)
