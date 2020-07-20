An auditing tool to detect incompatibilities in manifests written for upstream Kubernetes to be used on OpenShift

The tool searches the directory for specified issue regexes and prints out a summary of any incompatibilities found along with which files they appear in

Requires the following python imports:
```
import os
import re
import glob
import argparse
import configparser
import packaging.version
```

Usage:
```
usage: audit.py [-h] [-v VERSION] target

positional arguments:
  target                Target directory containing files to audit

optional arguments:
  -h, --help            show this help message and exit
  -v VERSION, --version VERSION
                        Target version of OpenShift to check against

```
