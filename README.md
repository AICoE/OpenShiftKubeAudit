An auditing tool to detect incompatibilities in manifests written for upstream Kubernetes to be used on OpenShift

The tool searches the directory for specified issue regexes and prints out a summary of any incompatibilities found along with which files they appear in

Requires the following python imports:
```
import jq
import os
import re
import glob
import yaml
import argparse
import configparser
import packaging.version
```

These are also provided as a requirements.txt for virtualenv creation

Usage:
```
usage: audit.py [-h] [-v VERSION] [-t TYPE] target

positional arguments:
  target                Target directory containing files to audit

optional arguments:
  -h, --help            show this help message and exit
  -v VERSION, --version VERSION
                        Target version of OpenShift to check against
  -t TYPE, --type TYPE  Type of audit to perform: yaml, go, helm. Currently OpenShift manifests (yaml) are the only supported type
```
