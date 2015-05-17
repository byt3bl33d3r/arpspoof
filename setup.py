#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read().replace('.. :changelog:', '')

requirements = [
    'scapy'
]

test_requirements = [
    # TODO: put package test requirements here
]

setup(
    name='arpspoof',
    version='0.1.0',
    description="Python clone of arpspoof that can poison hosts via arp-requests as well as arp-replies",
    long_description=readme + '\n\n' + history,
    author="byt3bl33d3r",
    author_email='byt3bl33d3r@gmail.com',
    url='https://github.com/byt3bl33d3r/arpspoof',
    packages=[
        'arpspoof',
    ],
    package_dir={'arpspoof':
                 'arpspoof'},
    include_package_data=True,
    install_requires=requirements,
    license="BSD",
    zip_safe=False,
    keywords='arpspoof',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
    test_suite='tests',
    tests_require=test_requirements,
    entry_points={
        'console_scripts': [
            'arpspoof = arpspoof.arpspoof:main',
        ]
    }
)
