#!/usr/bin/python

# Copyright: (c) 2022, Dee'Kej <devel@deekej.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: kerberos.ticket

short_description: Obtains new Kerberos ticket via username/password

version_added: "1.0.0"

description: Simple module for obtaining new Kerberos ticket via the
             username/password combination. Does nothing if a valid
             ticket already exists - unless force option is set to True.

options:
    username:
        description: Kerberos username to use
        required: true
        type: str

    password:
        description: Kerberos password to use
        required: true
        type: raw

    realm:
        description: Kerberos realm to use
        required: true
        type: str

    force:
        description: Forces obtaining of new Kerberos ticket - even when
                     a valid ticket already exists...
        required: false
        type: bool

    forwardable:
        description:
            - Uses system's default configuration when not specified.
            - Requests forwardable ticket when set to True.
            - Requests non-forwardable ticket when set to False.
        required: false
        type: bool

author:
    - Dee'Kej (@deekej)
'''

EXAMPLES = r'''
- name: Obtain new Kerberos ticket if needed
  kerberos.ticket:
    username:     deekej
    password:     nobody-will-read_this_anyway42
    realm:        IPA.REDHAT.COM

- name: Always obtain new Kerberos ticket
  kerberos.ticket:
    username:     deekej
    password:     nobody-will-read_this_anyway42
    realm:        IPA.REDHAT.COM
    force:        true

- name: Obtain new Kerberos ticket if needed (forwardable)
  kerberos.ticket:
    username:     deekej
    password:     nobody-will-read_this_anyway42
    realm:        IPA.REDHAT.COM
    forwardable:  true

- name: Obtain new Kerberos ticket if needed (non-forwardable)
  kerberos.ticket:
    username:     deekej
    password:     nobody-will-read_this_anyway42
    realm:        IPA.REDHAT.COM
    forwardable:  false
'''

# =====================================================================

import atexit
import gc
import os
from ansible.module_utils.basic import AnsibleModule

cmd = None
password = None

def clear_sensitive_data():
    global cmd, password
    del cmd, password
    gc.collect()

def run_module():
    global cmd, password

    # Ansible Module initialization:
    module_args = dict(
        username=dict(type='str', required=True),
        password=dict(type='raw', required=True, no_log=True),
        realm=dict(type='str', required=True),
        force=dict(type='bool', required=False, default=False),
        forwardable=dict(type='bool', required=False, default=None)
    )

    # Parsing of Ansible Module arguments:
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Make sure we clear the sensitive data no matter the result:
    atexit.register(clear_sensitive_data)

    username = module.params['username']
    password = module.params['password']
    realm = module.params['realm']
    force = module.params['force']

    if module.params['forwardable'] is None:
        forwardable = ''                    # System default
    elif module.params['forwardable']:
        forwardable = '-f'                  # Flag for forwardable ticket
    else:
        forwardable = '-F'                  # Flag for non-forwardable ticket

    principal = username + '@' + realm

    result = dict(
        changed = False,
        username = username,
        password = '[REDACTED]',
        realm = realm,
        principal = principal,
        force = force,
        forwardable = forwardable
    )

    # -----------------------------------------------------------------

    if module.check_mode:
        if not force:
            cmd = 'klist -s'
            shell = os.popen(cmd)

            # The close method returns None if the subprocess exited
            # successfully ->> valid Kerberos ticket exists...
            if not shell.close():
                # Check if the principal actually exists in the ccache:
                cmd = 'klist -l'
                shell = os.popen(cmd)
                cmd_output = shell.read()

                # Nothing to do, valid ticket exists, bail out...
                if cmd_output.find(principal) != -1:
                    module.exit_json(**result)

        result['changed'] = True
        module.exit_json(**result)

    # -----------------------------------------------------------------

    if force:
        cmd = "kdestroy -q -p %s 2>&1" % principal
        shell = os.popen(cmd)
        shell.close()
    else:
        cmd = 'klist -s'
        shell = os.popen(cmd)

        # The close method returns None if the subprocess exited
        # successfully ->> valid Kerberos ticket exists...
        if not shell.close():
            # Check if the principal actually exists in the ccache:
            cmd = 'klist -l'
            shell = os.popen(cmd)
            cmd_output = shell.read()

            # Nothing to do, valid ticket exists, bail out...
            if cmd_output.find(principal) != -1:
                module.exit_json(**result)

    # -----------------------------------------------------------------

    cmd = "echo -n '%s' | kinit %s %s 2>&1 >/dev/null" % (password, forwardable, principal)

    shell = os.popen(cmd)
    cmd_output = shell.read()

    if shell.close():
        module.fail_json(msg=cmd_output, **result)

    cmd = None
    password = None
    result['changed'] = True

    module.exit_json(**result)

# =====================================================================

def main():
    run_module()


if __name__ == '__main__':
    main()
