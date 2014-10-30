#!/usr/bin/env python
# encoding: utf-8

import sys
import logging


logging.basicConfig(
    level=logging.INFO,
    stream=sys.stdout,
    format='[%(asctime)s][%(levelname)s][%(name)s]: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
