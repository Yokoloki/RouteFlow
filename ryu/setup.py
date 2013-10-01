# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# a bug workaround.  http://bugs.python.org/issue15881
try:
    import multiprocessing
except ImportError:
    pass

import setuptools
import os


# the latest versions of pbr generate scripts which don't support
# multiversion.  to avoid importing modules from older multiversion-aware
# installations of ryu, we prefer multiversion-aware scripts.
PBR_VERSION = '0.5.19'

os.environ["PBR_VERSION"] = PBR_VERSION
setuptools.setup(name='ryu',
                 setup_requires=['pbr==%s' % (PBR_VERSION,)],
                 pbr=True)