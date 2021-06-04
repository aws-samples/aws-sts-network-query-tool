# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from setuptools import setup
from os import path
from io import open

import pathlib
# The directory containing this file
HERE = pathlib.Path(__file__).parent

# automatically captured required modules for install_requires in requirements.txt and as well as configure dependency links
with open(path.join(HERE, 'requirements.txt'), encoding='utf-8') as f:
    all_reqs = f.read().split('\n')
install_requires = [x.strip() for x in all_reqs if ('git+' not in x) and (
    not x.startswith('#')) and (not x.startswith('-'))]
dependency_links = [x.strip().replace('git+', '') for x in all_reqs \
                    if 'git+' not in x]

setup(
    name = 'aws-sts-network-query-tool',
    description = 'AWS STS Network Query Tool uses cross account roles to collect networking related information for multiple accounts and outputs a CSV.',
    version = '1.0.0',
    packages = ['aws_network_query'],
    install_requires = install_requires,
    python_requires='>=3.7',
    entry_points = {
        'console_scripts': [
            'aws_network_query = aws_network_query.app:main'
        ]
    },
     license='MIT',
     url='https://github.com/aws-samples/aws-sts-network-query-tool'
    )
