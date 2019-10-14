#!/usr/bin/env python
from ansible.module_utils.basic import AnsibleModule
import requests
from requests.auth import HTTPDigestAuth

DOCUMENTATION = '''
module: mongo_atlas_role
short_description: Module for provisioning roles in MongoDB Atlas
description:
    - This module provides the ability to provision roles on MongoDB instances
    - hosted in Atlas
version_added: "2.2"
author:
    - "David Castellanos (@davidcaste)
requirements:
    - MongoDB Atlas account access
    - MongoDB Atlas API key
options:
    atlas_api_public_key:
        description:
            - The API public key required to access MongoDB Atlas's REST API
        required: true
    atlas_api_private_key:
        description:
            - The API private key required to access MongoDB Atlas's REST API
        required: true
    atlas_group_id:
        description:
            - The group ID is a representation of your account ID in MongoDB
            - Atlas. To get it go to Settings > Group Settings.
        required: true
    state:
        description:
            - "'present' will create the user if the user does not exist and"
            - update existing users as needed
            - "'absent' removes the user if the user exists"
        required: false
        default: present
        choices: [present, absent]
    role_name:
        description:
            - The name of the new role.
        required: true
    actions:
        description:
            - Each object in the actions array represents an individual
            - privilege action granted by the role.
        required: false
        default: []
    inherited_roles:
        description:
            - Each object in the inherited_roles array represents a key-value
            - pair indicating the inherited role and the database on which the
            - role is granted.
        required: false
        default: []
'''

EXAMPLES = '''
    - name: create a role in atlas
      mongo_atlas_role:
        atlas_api_public_key: 'abcdefgh'
        atlas_api_private_key: '12345-678-90abcd-ef1234'
        atlas_group_id: 'abcabcabc123123123'
        state: present
        role_name: ShardingAdmin,
        actions:
            - action: CONN_POOL_STATS
              resources: [ { "cluster": true } ]
            - action: "COLL_STATS",
              resources: [ { "collection": "", "db": "staging" } ]
        inherited_roles:
            - db: "admin",
              role: "enableSharding"
            - db: "admin",
              role: "backup"
'''


def get_role(atlas_group_id, atlas_api_public_key, atlas_api_private_key,
             role_name):
    """
    Calls GET /api/atlas/v1.0/groups/{GROUP-ID}/customDBRoles/roles/{ROLE-NAME}

    Returns:
        The JSON of the role object with the URL called to get it added as
        'url' in the JSON
    """
    url = "https://cloud.mongodb.com/api/atlas/v1.0/groups/{}/customDBRoles/roles/{}".format(atlas_group_id, role_name)
    response = requests.get(url, auth=HTTPDigestAuth(atlas_api_public_key, atlas_api_private_key))
    role_json = response.json()
    response.close()
    role_json['url'] = url
    return role_json


def create_role(atlas_group_id, atlas_api_public_key, atlas_api_private_key,
                role_name, actions, inherited_roles):
    url = "https://cloud.mongodb.com/api/atlas/v1.0/groups/{}/customDBRoles/roles".format(atlas_group_id)
    role = {
        'actions': actions,
        'inheritedRoles': inherited_roles,
        'roleName': role_name
    }
    response = requests.post(url, json=role,
                             auth=HTTPDigestAuth(atlas_api_public_key,
                                                 atlas_api_private_key))
    post_json = response.json()
    response.close()
    post_json['url'] = url
    return post_json


def delete_role(atlas_group_id, atlas_api_public_key, atlas_api_private_key,
                role_name):
    url = "https://cloud.mongodb.com/api/atlas/v1.0/groups/{}/customDBRoles/roles/{}".format(atlas_group_id, role_name)
    return requests.delete(url, auth=HTTPDigestAuth(atlas_api_public_key, atlas_api_private_key))


def sync_role(atlas_group_id, atlas_api_public_key, atlas_api_private_key,
              role_name, actions, inherited_roles, http_response):
    if http_response['actions'] == actions and http_response['inheritedRoles'] == inherited_roles:
        return dict(changed=False)

    payload = {
        'actions': actions,
        'inheritedRoles': inherited_roles
    }

    url = "https://cloud.mongodb.com/api/atlas/v1.0/groups/{}/customDBRoles/roles/{}".format(atlas_group_id, role_name)
    response = requests.patch(url, json=payload, auth=HTTPDigestAuth(atlas_api_public_key, atlas_api_private_key))

    path_json = response.json()
    response.close()
    path_json['changed'] = True
    path_json['url'] = url
    return path_json

def main():
    """Load the option and route the methods to call"""
    module = AnsibleModule(
        argument_spec=dict(
            atlas_api_public_key=dict(required=True, type='str'),
            atlas_api_private_key=dict(required=True, type='str', no_log=True),
            atlas_group_id=dict(required=True, type='str'),
            state=dict(default='present', choices=['absent', 'present']),
            role_name=dict(required=True, type='str', no_log=False),
            actions=dict(default=None, type='list'),
            inherited_roles=dict(default=None, type='list')
        ),
        supports_check_mode=False
    )
    atlas_api_public_key = module.params['atlas_api_public_key']
    atlas_api_private_key = module.params['atlas_api_private_key']
    atlas_group_id = module.params['atlas_group_id']
    state = module.params['state']
    role_name = module.params['role_name']
    actions = module.params['actions']
    inherited_roles = module.params['inherited_roles']

    # Do an initial query for the role so we can inspect if it needs to change
    subject_response = get_role(atlas_group_id, atlas_api_public_key,
                                atlas_api_private_key, role_name)

    if subject_response.get('error') is None:
        subject_state = 'present'
    elif subject_response.get('error') == 404:
        subject_state = 'absent'
    else:
        module.fail_json(msg=str(subject_response))
        return

    # The role is not there so we must create it
    if state == 'present' and subject_state == 'absent':
        response = create_role(atlas_group_id, atlas_api_public_key,
                               atlas_api_private_key, role_name, actions,
                               inherited_roles)
        if response.get('error') is None:
            module.exit_json(changed=True, role=response)
        else:
            module.fail_json(msg='Failed to create role: {}'.format(response))
        return

    # The role is not there and we don't want it there. Nothing to do here
    if state == 'absent' and subject_state == 'absent':
        module.exit_json(changed=False, role=role_name)
        return

    # The role is there and we don't wait it to be. Delete it.
    if state == 'absent' and subject_state == 'present':
        response = delete_role(atlas_group_id, atlas_api_public_key,
                               atlas_api_private_key, role_name)
        try:
            response.raise_for_status()
        except Exception as err:
            module.fail_json(msg='Failed to delete role: {}'.format(err))
        else:
            module.exit_json(changed=True, role=role_name)

    # The role is there and we want it to be
    if state == 'present' and subject_state == 'present':
        response = sync_role(atlas_group_id, atlas_api_public_key,
                             atlas_api_private_key, role_name, actions,
                             inherited_roles, subject_response)
        if response.get('error') is None:
            module.exit_json(changed=response['changed'], user=subject_response)
        else:
            module.fail_json(msg='Failed to update role: {}'.format(response), subject=subject_response)
        return

if __name__ == '__main__':
    main()
