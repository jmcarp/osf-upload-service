# -*- coding: utf-8 -*-

import re
import sys
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand


REQUIRES = [

    # Tornado app
    'requests==2.4.1',
    'tornado==4.0.2',
    'webargs==0.6.2',

    # Task queue
    'celery==3.1.15',

    # Storage backends
    'boto==2.32.1',
    'pyrax==1.9.2',

    # Miscellaneous
    'six==1.8.0',
    'furl==0.3.95',
    'python-dateutil==2.2',
    'werkzeug==0.9.6',

]

TEST_REQUIRES = [
    'mock',
    'pytest',
    'httpretty',
    'pytest-httpretty',
]


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = [
            '--verbose'
        ]
        self.test_suite = True

    def run_tests(self):
        import pytest
        errcode = pytest.main(self.test_args)
        sys.exit(errcode)


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
    packages=find_packages(exclude=("test*", )),
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
    test_suite='tests',
    tests_require=TEST_REQUIRES,
    cmdclass={'test': PyTest},
)

