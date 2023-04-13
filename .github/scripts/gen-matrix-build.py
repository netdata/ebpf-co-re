#!/usr/bin/env python3

import json
import requests

distros_matrix = "https://raw.githubusercontent.com/netdata/netdata/master/.github/data/distros.yml"

from ruamel.yaml import YAML

yaml = YAML(typ='safe')
entries = []

r = requests.get(distros_matrix, allow_redirects=True)
data = yaml.load(r.content)

with open('.github/data/cached_vagrant_vms.json') as f:
    vagrant_vms = json.load(f)

for i, v in enumerate(data['include']):
    e = {
      'artifact_key': v['distro'] + str(v['version']).replace('.', ''),
      'version': v['version'],
    }

    if 'base_image' in v:
        e['distro'] = v['base_image']
    else:
        e['distro'] = ':'.join([v['distro'], str(v['version'])])

    if 'env_prep' in v:
        e['env_prep'] = v['env_prep']

    if 'jsonc_removal' in v:
        e['jsonc_removal'] = v['jsonc_removal']

    entries.append(e)

entries.sort(key=lambda k: k['distro'])
matrix = json.dumps({'include': entries}, sort_keys=True, indent=4)
print(matrix)

print(json.dumps(vagrant_vms, indent=4))

