#!/usr/bin/python
# SPDX-FileCopyrightText: 2025-2026 VectoDE
#
# SPDX-License-Identifier: MIT

"""Ansible module vectode.lss.lss: installs and removes lss modules through the lss command."""

from __future__ import annotations

import os
import re

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = r"""
---
module: lss
short_description: Install and remove lss modules
version_added: "2.0.0"
description:
  - Runs C(lss install) or C(lss remove) on the target, the command that sets up and hardens the server.
  - Install lss first with the role M(vectode.lss.lss) or with C(bootstrap.sh), both of which verify the release.
  - A module counts as changed when lss reports changes for it, so a second run with the same settings reports no change.
author:
  - VectoDE (@VectoDE)
options:
  modules:
    description:
      - lss modules to install or remove, such as V(nginx) or V(ssh-hardening). C(lss list) shows them all.
      - Modules they require are installed with them.
    type: list
    elements: str
    default: []
  profile:
    description:
      - Profile to install, such as V(minimal-secure). Only with O(state=present).
    type: str
  state:
    description:
      - V(present) installs the modules and applies their settings, V(absent) removes them.
    type: str
    choices: [present, absent]
    default: present
  settings:
    description:
      - Settings for this run, each passed as C(--set KEY=VALUE), on top of C(/etc/lss/lss.conf).
      - Keys are named C(LSS_<MODULE>_<OPTION>); C(lss info MODULE) lists them.
    type: dict
    default: {}
  mode:
    description:
      - How services that support both are installed.
    type: str
    choices: [native, docker]
  purge:
    description:
      - With O(state=absent), also delete the data of the modules.
    type: bool
    default: false
  executable:
    description:
      - Path of the lss command.
    type: path
    default: /usr/local/sbin/lss
attributes:
  check_mode:
    support: full
    description: Runs C(lss --dry-run install), which checks every setting, and reports a change for each module that is not installed yet.
  diff_mode:
    support: none
notes:
  - Runs as root on the target (C(become=true)).
"""

EXAMPLES = r"""
- name: Harden the server
  vectode.lss.lss:
    profile: minimal-secure
    settings:
      LSS_ADMIN_USER_NAME: alice
      LSS_ADMIN_USER_GITHUB_USER: alice-on-github

- name: Web server with certificates
  vectode.lss.lss:
    modules: [nginx, tls, vhost]
    settings:
      LSS_TLS_DOMAINS: www.example.com
      LSS_VHOST_SITES: "site:static:www.example.com"

- name: Remove Adminer and its data
  vectode.lss.lss:
    modules: [adminer]
    state: absent
    purge: true
"""

RETURN = r"""
changed_modules:
  description: Modules that were installed, changed or removed (in check mode, that would be).
  returned: always
  type: list
  elements: str
  sample: [nginx, tls]
stdout_lines:
  description: Output of the lss runs.
  returned: always
  type: list
  elements: str
"""

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
KEY_RE = re.compile(r"^LSS_[A-Z0-9_]+$")
DONE_RE = re.compile(r"^OK +([a-z0-9-]+): done", re.MULTILINE)
ORDER_RE = re.compile(r"Modules in order: ([a-z0-9 -]+)$", re.MULTILINE)


def lss_command(module, *args):
    """Runs lss without prompts and colours with the global options of this task; fails the task on an error."""
    params = module.params
    command = [params["executable"], "--yes", "--no-color"]
    if params["mode"]:
        command += ["--mode", params["mode"]]
    for key, value in sorted(params["settings"].items()):
        command += ["--set", f"{key}={value_text(value)}"]
    command += list(args)
    rc, stdout, stderr = module.run_command(command)
    output = stdout + stderr
    if rc != 0:
        module.fail_json(msg=f"lss {' '.join(args)} failed (exit status {rc})", rc=rc, stdout_lines=output.splitlines())
    return output


def value_text(value):
    """Booleans as lss reads them (true/false), everything else as text."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def installed_modules(module):
    """Names of the modules lss lists as installed."""
    output = lss_command(module, "status")
    names = set()
    for line in output.splitlines():
        if not line.strip() or line.startswith("Failed services"):
            break
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "installed":
            names.add(fields[0])
    return names


def check_params(module):
    params = module.params
    for name in params["modules"] + ([params["profile"]] if params["profile"] else []):
        if not NAME_RE.match(name):
            module.fail_json(msg=f"'{name}' is a module or profile name like nginx or minimal-secure.")
    for key, value in params["settings"].items():
        if not KEY_RE.match(key):
            module.fail_json(msg=f"'{key}' is a setting name like LSS_NGINX_MAX_BODY.")
        if "\n" in value_text(value):
            module.fail_json(msg=f"The value of {key} spans more than one line.")
    if params["state"] == "present" and not params["modules"] and not params["profile"]:
        module.fail_json(msg="Name modules or a profile to install.")
    if params["state"] == "absent" and params["profile"]:
        module.fail_json(msg="state=absent removes modules; name them in modules, not as a profile.")


def present(module):
    params = module.params
    target = ["--profile", params["profile"]] if params["profile"] else []
    target += params["modules"]
    if module.check_mode:
        output = lss_command(module, "--dry-run", "install", *target)
        order = ORDER_RE.search(output)
        wanted = order.group(1).split() if order else params["modules"]
        installed = installed_modules(module)
        return [name for name in wanted if name not in installed], output
    output = lss_command(module, "install", *target)
    return DONE_RE.findall(output), output


def absent(module):
    params = module.params
    installed = installed_modules(module)
    removed = []
    output = ""
    for name in reversed(params["modules"]):
        if name not in installed:
            continue
        removed.append(name)
        if not module.check_mode:
            output += lss_command(module, "remove", name, *(["--purge"] if params["purge"] else []))
    return removed, output


def main():
    module = AnsibleModule(
        argument_spec={
            "modules": {"type": "list", "elements": "str", "default": []},
            "profile": {"type": "str"},
            "state": {"type": "str", "choices": ["present", "absent"], "default": "present"},
            "settings": {"type": "dict", "default": {}},
            "mode": {"type": "str", "choices": ["native", "docker"]},
            "purge": {"type": "bool", "default": False},
            "executable": {"type": "path", "default": "/usr/local/sbin/lss"},
        },
        supports_check_mode=True,
    )
    check_params(module)
    if not os.access(module.params["executable"], os.X_OK):
        if module.check_mode:
            module.exit_json(changed=True, changed_modules=module.params["modules"], stdout_lines=[],
                             msg="lss is not installed yet; the role vectode.lss.lss installs it first.")
        module.fail_json(msg=f"{module.params['executable']} is missing; install lss first (role vectode.lss.lss).")
    if module.params["state"] == "present":
        changed, output = present(module)
    else:
        changed, output = absent(module)
    module.exit_json(changed=bool(changed), changed_modules=changed, stdout_lines=output.splitlines())


if __name__ == "__main__":
    main()
