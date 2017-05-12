#!/usr/bin/python

import httplib2
import apiclient.discovery
import apiclient.http
import apiclient.errors
import oauth2client.client
import sys
import pprint
import os

def get_drive_service():
    OAUTH2_SCOPE = 'https://www.googleapis.com/auth/drive'
    CLIENT_SECRETS = 'client_secrets.json'
    flow = oauth2client.client.flow_from_clientsecrets(CLIENT_SECRETS, OAUTH2_SCOPE)
    flow.redirect_uri = oauth2client.client.OOB_CALLBACK_URN
    authorize_url = flow.step1_get_authorize_url()
    print('Use this link for authorization:\n{}'.format(authorize_url))
    if sys.version_info[0] > 2:
        code = input('Verification code: ').strip()
    else:
        code = raw_input('Verification code: ').strip()
    credentials = flow.step2_exchange(code)
    http = httplib2.Http()
    credentials.authorize(http)
    drive_service = apiclient.discovery.build('drive', 'v3', http=http)
    return drive_service

def show_info(service, drive_item, prefix, permission_id):
    try:
        print(os.path.join(prefix, drive_item['name']))
        print('Would set new owner to {}.'.format(permission_id))
    except KeyError:
        print('No name for this item:')
        pprint.pprint(drive_item)

class PermissionMatcher(object):
    def __init__(self):
        raise ValueError("Unimplemented")

    def matches(self, permission):
        """ Return true if this permission matches """
        raise ValueError("Unimplemented")

class PermissionMatchDomain(PermissionMatcher):
    def __init__(self, domain):
        self.domain = domain
    def matches(self, permission):
        return permission.get('domain') == self.domain or \
               permission.get('emailAddress', '').endswith('@' + self.domain)

def revoke_permissions(service, drive_item, prefix, permission_matcher, show_unchanged):
    full_path = os.path.join(os.path.sep.join(prefix), drive_item['name']).encode('utf-8', 'replace')

    pprint.pprint(drive_item)

    for permission in drive_item['permissions']:
        if permission.get('deleted') == True:
            continue
        if permission_matcher.matches(permission):
            print('Item {} should be revoked from {}'.format(full_path, permission['emailAddress']))
            try:
                permission = service.permissions().delete(fileId=drive_item['id'], permissionId=permission['id']).execute()
            except apiclient.errors.HttpError as e:
                if e.resp.status != 404:
                    print('An error occurred updating ownership permissions: {}'.format(e))
        else:
            print('Item {} does not need to be revoked from {}'.format(full_path, permission['emailAddress']))

def process_all_files(service, callback=None, callback_args=None, minimum_prefix=None, current_prefix=None, folder_id='root'):
    if minimum_prefix is None:
        minimum_prefix = []
    if current_prefix is None:
        current_prefix = []
    if callback_args is None:
        callback_args = []

    print('Gathering file listings for prefix {}...'.format(current_prefix))

    page_token = None
    while True:
        try:
            param = {}
            if page_token:
                param['pageToken'] = page_token
            files = service.files().list(q="'{}' in parents".format(folder_id), fields='files(kind,mimeType,id,name,permissions)', **param).execute()
            for item in files.get('files', []):
                #pprint.pprint(item)
                if item['kind'] == 'drive#file':
                    if current_prefix[:len(minimum_prefix)] == minimum_prefix:
                        print(u'File: {} ({}, {})'.format(item['name'], current_prefix, item['id']))
                        callback(service, item, current_prefix, **callback_args)
                    if item['mimeType'] == 'application/vnd.google-apps.folder':
                        print(u'Folder: {} ({}, {})'.format(item['name'], current_prefix, item['id']))
                        next_prefix = current_prefix + [item['name']]
                        comparison_length = min(len(next_prefix), len(minimum_prefix))
                        if minimum_prefix[:comparison_length] == next_prefix[:comparison_length]:
                            process_all_files(service, callback, callback_args, minimum_prefix, next_prefix, item['id'])
            page_token = files.get('nextPageToken')
            if not page_token:
                break
        except apiclient.errors.HttpError as e:
            print('An error occurred: {}'.format(e))
            break

if __name__ == '__main__':
    if sys.version_info[0] > 2:
        minimum_prefix = sys.argv[1]
        revoke_domain = sys.argv[2]
        show_unchanged = False if len(sys.argv) > 3 and sys.argv[3] == 'false' else True
    else:
        minimum_prefix = sys.argv[1].decode('utf-8')
        revoke_domain = sys.argv[2].decode('utf-8')
        show_unchanged = False if len(sys.argv) > 3 and sys.argv[3].decode('utf-8') == 'false' else True
    print('Changing all files at path "{}"'.format(minimum_prefix))
    minimum_prefix_split = minimum_prefix.split(os.path.sep)
    print('Prefix: {}'.format(minimum_prefix_split))
    service = get_drive_service()
    permission_matcher = PermissionMatchDomain(revoke_domain)
    process_all_files(service, revoke_permissions, {'permission_matcher': permission_matcher, 'show_unchanged': show_unchanged }, minimum_prefix_split)
    #print(files)
