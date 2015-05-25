# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2013 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

""" yunohost_app.py

    Manage apps
"""
import os
import sys
import json
import shutil
import stat
import yaml
import time
import re
import socket
import urlparse
import errno
from collections import OrderedDict

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

repo_path        = '/var/cache/yunohost/repo'
apps_path        = '/usr/share/yunohost/apps'
apps_setting_path= '/etc/yunohost/apps'
install_tmp      = '/var/cache/yunohost'
app_tmp_folder   = install_tmp + '/from_file'

logger = getActionLogger('yunohost.app')


def app_listlists():
    """
    List fetched lists


    """
    list_list = []
    try:
        for filename in os.listdir(repo_path):
            if '.json' in filename:
                list_list.append(filename[:len(filename)-5])
    except OSError:
        raise MoulinetteError(1, m18n.n('no_appslist_found'))

    return { 'lists' : list_list }


def app_fetchlist(url=None, name=None):
    """
    Fetch application list from app server

    Keyword argument:
        name -- Name of the list (default yunohost)
        url -- URL of remote JSON list (default http://app.yunohost.org/list.json)

    """
    # Create app path if not exists
    try: os.listdir(repo_path)
    except OSError: os.makedirs(repo_path)

    if url is None:
        url = 'http://app.yunohost.org/list.json'
        name = 'yunohost'
    else:
        if name is None:
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('custom_appslist_name_required'))

    list_file = '%s/%s.json' % (repo_path, name)
    if os.system('wget "%s" -O "%s.tmp"' % (url, list_file)) != 0:
        os.remove('%s.tmp' % list_file)
        raise MoulinetteError(errno.EBADR, m18n.n('appslist_retrieve_error'))

    # Rename fetched temp list
    os.rename('%s.tmp' % list_file, list_file)

    os.system("touch /etc/cron.d/yunohost-applist-%s" % name)
    os.system("echo '00 00 * * * root yunohost app fetchlist -u %s -n %s > /dev/null 2>&1' >/etc/cron.d/yunohost-applist-%s" % (url, name, name))

    msignals.display(m18n.n('appslist_fetched'), 'success')


def app_removelist(name):
    """
    Remove list from the repositories

    Keyword argument:
        name -- Name of the list to remove

    """
    try:
        os.remove('%s/%s.json' % (repo_path, name))
        os.remove("/etc/cron.d/yunohost-applist-%s" % name)
    except OSError:
        raise MoulinetteError(errno.ENOENT, m18n.n('appslist_unknown'))

    msignals.display(m18n.n('appslist_removed'), 'success')


def app_list(offset=None, limit=None, filter=None, raw=False):
    """
    List apps

    Keyword argument:
        filter -- Name filter of app_id or app_name
        offset -- Starting number for app fetching
        limit -- Maximum number of app fetched
        raw -- Return the full app_dict

    """
    if offset: offset = int(offset)
    else: offset = 0
    if limit: limit = int(limit)
    else: limit = 1000

    applists = os.listdir(repo_path)
    app_dict  = {}
    if raw:
        list_dict = {}
    else:
        list_dict=[]

    if not applists:
        app_fetchlist()
        applists = os.listdir(repo_path)

    for applist in applists:
        if '.json' in applist:
            with open('{0}/{1}'.format(repo_path, applist)) as json_list:
                app_dict.update(json.loads(str(json_list.read())))

    for app in os.listdir(apps_setting_path):
        if app not in app_dict:
            # Look for forks
            if '__' in app:
                original_app = app[:app.index('__')]
                if original_app in app_dict:
                    app_dict[app] = app_dict[original_app]
                    continue
            with open('{0}/{1}/manifest.json'.format(
                    apps_setting_path, app)) as json_manifest:
                app_dict[app] = {"manifest":json.loads(str(json_manifest.read()))}
            app_dict[app]['manifest']['orphan']=True

    if len(app_dict) > (0 + offset) and limit > 0:
        sorted_app_dict = {}
        for sorted_keys in sorted(app_dict.keys())[offset:]:
            sorted_app_dict[sorted_keys] = app_dict[sorted_keys]

        i = 0
        for app_id, app_info in sorted_app_dict.items():
            if i < limit:
                if (filter and ((filter in app_id) or (filter in app_info['manifest']['name']))) or not filter:
                    installed = _is_installed(app_id)

                    if raw:
                        app_info['installed'] = installed
                        list_dict[app_id] = app_info
                    else:
                        list_dict.append({
                            'id': app_id,
                            'name': app_info['manifest']['name'],
                            'description': _value_for_locale(
                                app_info['manifest']['description']),
                            # FIXME: Temporarly allow undefined license
                            'license': app_info['manifest'].get('license',
                                m18n.n('license_undefined')),
                            'installed': installed
                        })
                    i += 1
            else:
               break
    if not raw:
        list_dict = { 'apps': list_dict }
    return list_dict


def app_info(app, raw=False):
    """
    Get app info

    Keyword argument:
        app -- Specific app ID
        raw -- Return the full app_dict

    """
    try:
        # Load info from list first...
        app = Application.from_app_id(app)
    except ValueError:
        logger.info("unable to find application '%s' in lists", app)
        try:
            # ... then from installed apps
            app = Application.from_installed_app(app)
        except ValueError:
            logger.exception("neither in installed applications")
            raise MoulinetteError(errno.EINVAL, m18n.n('app_unknown'))

    if not raw:
        return app.get_global_info()
    else:
        return {
            'settings': app.settings,
            'manifest': app.manifest,
            'installed': app.is_installed,
            # FIXME: Calls wich need 'lastUpdate' and 'git' are broken!
            # TODO: Add a remote key with git settings and list name
        }


def app_map(app=None, raw=False, user=None):
    """
    List apps by domain

    Keyword argument:
        user -- Allowed app map for a user
        raw -- Return complete dict
        app -- Specific app to map

    """

    result = {}

    for app_id in os.listdir(apps_setting_path):
        if app and (app != app_id):
            continue

        if user is not None:
            app_dict = app_info(app=app_id, raw=True)
            if ('mode' not in app_dict['settings']) or ('mode' in app_dict['settings'] and app_dict['settings']['mode'] == 'private'):
                if 'allowed_users' in app_dict['settings'] and user not in app_dict['settings']['allowed_users'].split(','):
                    continue

        with open('{0}/{1}/settings.yml'.format(
                apps_setting_path, app_id)) as f:
            app_settings = yaml.load(f)

        if 'domain' not in app_settings:
            continue

        if raw:
            if app_settings['domain'] not in result:
                result[app_settings['domain']] = {}
            result[app_settings['domain']][app_settings['path']] = {
                    'label': app_settings['label'],
                    'id': app_settings['id']
            }
        else:
            result[app_settings['domain']+app_settings['path']] = app_settings['label']

    return result


def app_upgrade(auth, app=[], url=None, file=None):
    """
    Upgrade app

    Keyword argument:
        file -- Folder or tarball for upgrade
        app -- App(s) to upgrade (default all)
        url -- Git url to fetch for upgrade

    """
    from yunohost.hook import hook_add, hook_exec

    try:
        app_list()
    except MoulinetteError:
        raise MoulinetteError(errno.ENODATA, m18n.n('app_no_upgrade'))

    upgraded_apps = []

    # If no app is specified, upgrade all apps
    if not app:
        if (not url and not file):
            app = os.listdir(apps_setting_path)
    elif not isinstance(app, list):
        app = [ app ]

    for app_id in app:
        installed = _is_installed(app_id)
        if not installed:
            raise MoulinetteError(errno.ENOPKG,
                                  m18n.n('app_not_installed', app_id))

        if app_id in upgraded_apps:
            continue

        if '__' in app_id:
            original_app_id = app_id[:app_id.index('__')]
        else:
            original_app_id = app_id

        current_app_dict = app_info(app_id,  raw=True)
        new_app_dict     = app_info(original_app_id, raw=True)

        if file:
            manifest = _extract_app_from_file(file)
        elif url:
            manifest = _fetch_app_from_git(url)
        elif new_app_dict is None or 'lastUpdate' not in new_app_dict or 'git' not in new_app_dict:
            msignals.display(m18n.n('custom_app_url_required', app_id), 'warning')
            continue
        elif (new_app_dict['lastUpdate'] > current_app_dict['lastUpdate']) \
              or ('update_time' not in current_app_dict['settings'] \
                   and (new_app_dict['lastUpdate'] > current_app_dict['settings']['install_time'])) \
              or ('update_time' in current_app_dict['settings'] \
                   and (new_app_dict['lastUpdate'] > current_app_dict['settings']['update_time'])):
            manifest = _fetch_app_from_git(app_id)
        else:
            continue

        # Check min version
        if 'min_version' in manifest and __version__ < manifest['min_version']:
            raise MoulinetteError(errno.EPERM,
                                  m18n.n('app_recent_version_required', app_id))

        app_setting_path = '{0}/{1}'.format(apps_setting_path, app_id)

        if original_app_id != app_id:
            # Replace original_app_id with the forked one in scripts
            for file in os.listdir(app_tmp_folder +'/scripts'):
                #TODO: do it with sed ?
                if file[:1] != '.':
                    with open(app_tmp_folder +'/scripts/'+ file, "r") as sources:
                        lines = sources.readlines()
                    with open(app_tmp_folder +'/scripts/'+ file, "w") as sources:
                        for line in lines:
                            sources.write(re.sub(r''+ original_app_id +'', app_id, line))

            if 'hooks' in os.listdir(app_tmp_folder):
                for file in os.listdir(app_tmp_folder +'/hooks'):
                    #TODO: do it with sed ?
                    if file[:1] != '.':
                        with open(app_tmp_folder +'/hooks/'+ file, "r") as sources:
                            lines = sources.readlines()
                        with open(app_tmp_folder +'/hooks/'+ file, "w") as sources:
                            for line in lines:
                                sources.write(re.sub(r''+ original_app_id +'', app_id, line))

        # Add hooks
        if 'hooks' in os.listdir(app_tmp_folder):
            for file in os.listdir(app_tmp_folder +'/hooks'):
                hook_add(app_id, app_tmp_folder +'/hooks/'+ file)

        # Execute App upgrade script
        os.system('chown -hR admin: %s' % install_tmp)
        if hook_exec(app_tmp_folder +'/scripts/upgrade') != 0:
            #TODO: display fail messages from script
            pass
        else:
            app_setting(app_id, 'update_time', int(time.time()))

        # Replace scripts and manifest
        os.system('rm -rf "%s/scripts" "%s/manifest.json"' % (app_setting_path, app_setting_path))
        os.system('mv "%s/manifest.json" "%s/scripts" %s' % (app_tmp_folder, app_tmp_folder, app_setting_path))

        # So much win
        upgraded_apps.append(app_id)
        msignals.display(m18n.n('app_upgraded', app_id), 'success')

    if not upgraded_apps:
        raise MoulinetteError(errno.ENODATA, m18n.n('app_no_upgrade'))

    msignals.display(m18n.n('upgrade_complete'), 'success')


def app_install(auth, app, label=None, args=None):
    """
    Install apps

    Keyword argument:
        app -- Name, local path or git URL of the app to install
        label -- Custom name for the app
        args -- Serialize arguments for app installation

    """
    from yunohost.hook import hook_add, hook_remove, hook_exec

    # Fetch or extract sources
    try: os.listdir(install_tmp)
    except OSError: os.makedirs(install_tmp)

    if app in app_list(raw=True) or ('@' in app) or ('http://' in app) or ('https://' in app):
        manifest = _fetch_app_from_git(app)
    elif os.path.exists(app):
        manifest = _extract_app_from_file(app)
    else:
        raise MoulinetteError(errno.EINVAL, m18n.n('app_unknown'))

    # Check ID
    if 'id' not in manifest or '__' in manifest['id']:
        raise MoulinetteError(errno.EINVAL, m18n.n('app_id_invalid'))

    app_id = manifest['id']

    # Check min version
    if 'min_version' in manifest and __version__ < manifest['min_version']:
        raise MoulinetteError(errno.EPERM,
                              m18n.n('app_recent_version_required', app_id))

    # Check if app can be forked
    instance_number = _installed_instance_number(app_id, last=True) + 1
    if instance_number > 1 :
        if 'multi_instance' not in manifest or not is_true(manifest['multi_instance']):
            raise MoulinetteError(errno.EEXIST,
                                  m18n.n('app_already_installed', app_id))

        app_id_forked = app_id + '__' + str(instance_number)

        # Replace app_id with the new one in scripts
        for file in os.listdir(app_tmp_folder +'/scripts'):
            #TODO: do it with sed ?
            if file[:1] != '.':
                with open(app_tmp_folder +'/scripts/'+ file, "r") as sources:
                    lines = sources.readlines()
                with open(app_tmp_folder +'/scripts/'+ file, "w") as sources:
                    for line in lines:
                        sources.write(re.sub(r''+ app_id +'', app_id_forked, line))

        if 'hooks' in os.listdir(app_tmp_folder):
            for file in os.listdir(app_tmp_folder +'/hooks'):
                #TODO: do it with sed ?
                if file[:1] != '.':
                    with open(app_tmp_folder +'/hooks/'+ file, "r") as sources:
                        lines = sources.readlines()
                    with open(app_tmp_folder +'/hooks/'+ file, "w") as sources:
                        for line in lines:
                            sources.write(re.sub(r''+ app_id +'', app_id_forked, line))

        # Change app_id for the rest of the process
        app_id = app_id_forked

    # Prepare App settings
    app_setting_path = '{0}/{1}'.format(apps_setting_path, app_id)

    #TMP: Remove old settings
    if os.path.exists(app_setting_path): shutil.rmtree(app_setting_path)
    os.makedirs(app_setting_path)
    os.system('touch %s/settings.yml' % app_setting_path)

    # Add hooks
    if 'hooks' in os.listdir(app_tmp_folder):
        for file in os.listdir(app_tmp_folder +'/hooks'):
            hook_add(app_id, app_tmp_folder +'/hooks/'+ file)

    app_setting(app_id, 'id', app_id)
    app_setting(app_id, 'install_time', int(time.time()))

    if label:
        app_setting(app_id, 'label', label)
    else:
        app_setting(app_id, 'label', manifest['name'])

    os.system('chown -R admin: '+ app_tmp_folder)

    try:
        if args is None:
            args = ''
        args_dict = dict(urlparse.parse_qsl(args))
    except:
        args_dict = {}

    # Execute App install script
    os.system('chown -hR admin: %s' % install_tmp)
    # Move scripts and manifest to the right place
    os.system('cp %s/manifest.json %s' % (app_tmp_folder, app_setting_path))
    os.system('cp -R %s/scripts %s' % (app_tmp_folder, app_setting_path))
    try:
        if hook_exec(app_tmp_folder + '/scripts/install', args_dict) == 0:
            shutil.rmtree(app_tmp_folder)
            os.system('chmod -R 400 %s' % app_setting_path)
            os.system('chown -R root: %s' % app_setting_path)
            os.system('chown -R admin: %s/scripts' % app_setting_path)
            app_ssowatconf(auth)
            msignals.display(m18n.n('installation_complete'), 'success')
        else:
            raise MoulinetteError(errno.EIO, m18n.n('installation_failed'))
    except:
        # Execute remove script and clean folders
        hook_remove(app_id)
        shutil.rmtree(app_setting_path)
        shutil.rmtree(app_tmp_folder)

        # Reraise proper exception
        try:
            raise
        except MoulinetteError:
            raise
        except KeyboardInterrupt, EOFError:
            raise MoulinetteError(errno.EINTR, m18n.g('operation_interrupted'))
        except Exception as e:
            import traceback
            msignals.display(traceback.format_exc().strip(), 'log')
            raise MoulinetteError(errno.EIO, m18n.n('unexpected_error'))


def app_remove(auth, app):
    """
    Remove app

    Keyword argument:
        app -- App(s) to delete

    """
    from yunohost.hook import hook_exec, hook_remove

    if not _is_installed(app):
        raise MoulinetteError(errno.EINVAL, m18n.n('app_not_installed', app))

    app_setting_path = '{0}/{1}'.format(apps_setting_path, app_id)

    #TODO: display fail messages from script
    try:
        shutil.rmtree('/tmp/yunohost_remove')
    except: pass

    os.system('cp -a %s /tmp/yunohost_remove && chown -hR admin: /tmp/yunohost_remove' % app_setting_path)
    os.system('chown -R admin: /tmp/yunohost_remove')
    os.system('chmod -R u+rX /tmp/yunohost_remove')

    if hook_exec('/tmp/yunohost_remove/scripts/remove') != 0:
        pass

    if os.path.exists(app_setting_path): shutil.rmtree(app_setting_path)
    shutil.rmtree('/tmp/yunohost_remove')
    hook_remove(app)
    app_ssowatconf(auth)
    msignals.display(m18n.n('app_removed', app), 'success')


def app_addaccess(auth, apps, users=[]):
    """
    Grant access right to users (everyone by default)

    Keyword argument:
        users
        apps

    """
    from yunohost.user import user_list, user_info
    from yunohost.hook import hook_callback

    if not users:
        users = user_list(auth)['users'].keys()

    if not isinstance(users, list): users = [users]
    if not isinstance(apps, list): apps = [apps]

    for app in apps:
        if not _is_installed(app):
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('app_not_installed', app))

        with open('{0}/{1}/settings.yml'.format(
                apps_setting_path, app_id)) as f:
            app_settings = yaml.load(f)

        if 'mode' not in app_settings:
            app_setting(app, 'mode', 'private')
            app_settings['mode'] = 'private'

        if app_settings['mode'] == 'private':
            if 'allowed_users' in app_settings:
                new_users = app_settings['allowed_users']
            else:
                new_users = ''

            for allowed_user in users:
                if allowed_user not in new_users.split(','):
                    try:
                        user_info(auth, allowed_user)
                    except MoulinetteError:
                        continue
                    if new_users == '':
                        new_users = allowed_user
                    else:
                        new_users = new_users +','+ allowed_user

            app_setting(app, 'allowed_users', new_users.strip())
            hook_callback('post_app_addaccess', args=[app, new_users])

    app_ssowatconf(auth)

    return { 'allowed_users': new_users.split(',') }


def app_removeaccess(auth, apps, users=[]):
    """
    Revoke access right to users (everyone by default)

    Keyword argument:
        users
        apps

    """
    from yunohost.user import user_list
    from yunohost.hook import hook_callback

    remove_all = False
    if not users:
        remove_all = True
    if not isinstance(users, list): users = [users]
    if not isinstance(apps, list): apps = [apps]
    for app in apps:
        new_users = ''

        if not _is_installed(app):
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('app_not_installed', app))

        with open('{0}/{1}/settings.yml'.format(
                apps_setting_path, app_id)) as f:
            app_settings = yaml.load(f)

        if 'skipped_uris' not in app_settings or app_settings['skipped_uris'] != '/':
            if remove_all:
                new_users = ''
            elif 'allowed_users' in app_settings:
                for allowed_user in app_settings['allowed_users'].split(','):
                    if allowed_user not in users:
                        if new_users == '':
                            new_users = allowed_user
                        else:
                            new_users = new_users +','+ allowed_user
            else:
                new_users = ''
                for username in user_list(auth)['users'].keys():
                    if username not in users:
                        if new_users == '':
                            new_users = username
                        new_users += ',' + username

            app_setting(app, 'allowed_users', new_users.strip())
            hook_callback('post_app_removeaccess', args=[app, new_users])

    app_ssowatconf(auth)

    return { 'allowed_users': new_users.split(',') }


def app_clearaccess(auth, apps):
    """
    Reset access rights for the app

    Keyword argument:
        apps

    """
    from yunohost.hook import hook_callback

    if not isinstance(apps, list): apps = [apps]

    for app in apps:
        if not _is_installed(app):
            raise MoulinetteError(errno.EINVAL,
                                  m18n.n('app_not_installed', app))

        with open('{0}/{1}/settings.yml'.format(
                apps_setting_path, app_id)) as f:
            app_settings = yaml.load(f)

        if 'mode' in app_settings:
            app_setting(app, 'mode', delete=True)

        if 'allowed_users' in app_settings:
            app_setting(app, 'allowed_users', delete=True)

        hook_callback('post_app_clearaccess', args=[app])

    app_ssowatconf(auth)


def app_makedefault(auth, app, domain=None):
    """
    Redirect domain root to an app

    Keyword argument:
        app
        domain

    """
    from yunohost.domain import domain_list

    if not _is_installed(app):
        raise MoulinetteError(errno.EINVAL, m18n.n('app_not_installed', app))

    with open('{0}/{1}/settings.yml'.format(apps_setting_path, app_id)) as f:
        app_settings = yaml.load(f)

    app_domain = app_settings['domain']
    app_path   = app_settings['path']

    if domain is None:
        domain = app_domain
    elif domain not in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EINVAL, m18n.n('domain_unknown'))

    if '/' in app_map(raw=True)[domain]:
        raise MoulinetteError(errno.EEXIST,
                              m18n.n('app_location_already_used'))

    try:
        with open('/etc/ssowat/conf.json.persistent') as json_conf:
            ssowat_conf = json.loads(str(json_conf.read()))
    except IOError:
        ssowat_conf = {}

    if 'redirected_urls' not in ssowat_conf:
        ssowat_conf['redirected_urls'] = {}

    ssowat_conf['redirected_urls'][domain +'/'] = app_domain + app_path

    with open('/etc/ssowat/conf.json.persistent', 'w+') as f:
        json.dump(ssowat_conf, f, sort_keys=True, indent=4)

    os.system('chmod 644 /etc/ssowat/conf.json.persistent')

    msignals.display(m18n.n('ssowat_conf_updated'), 'success')


def app_setting(app, key, value=None, delete=False):
    """
    Set or get an app setting value

    Keyword argument:
        value -- Value to set
        app -- App ID
        key -- Key to get/set
        delete -- Delete the key

    """
    settings_file = '{0}/{1}/settings.yml'.format(apps_setting_path, app_id)

    try:
        with open(settings_file) as f:
            app_settings = yaml.load(f)
    except IOError:
        # Do not fail if setting file is not there
        app_settings = {}

    if value is None and not delete:
        # Get the value
        if app_settings is not None and key in app_settings:
            return app_settings[key]
    else:
        yaml_settings=['redirected_urls','redirected_regex']
        # Set the value
        if app_settings is None:
            app_settings = {}
        if delete and key in app_settings:
            del app_settings[key]
        else:
            if key in yaml_settings:
                value=yaml.load(value)
            app_settings[key] = value

        with open(settings_file, 'w') as f:
            yaml.safe_dump(app_settings, f, default_flow_style=False)


def app_checkport(port):
    """
    Check availability of a local port

    Keyword argument:
        port -- Port to check

    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("localhost", int(port)))
        s.close()
    except socket.error:
        msignals.display(m18n.n('port_available', int(port)), 'success')
    else:
        raise MoulinetteError(errno.EINVAL,
                              m18n.n('port_unavailable', int(port)))


def app_checkurl(auth, url, app=None):
    """
    Check availability of a web path

    Keyword argument:
        url -- Url to check
        app -- Write domain & path to app settings for further checks

    """
    from yunohost.domain import domain_list

    if "https://" == url[:8]:
        url = url[8:]
    elif "http://" == url[:7]:
        url = url[7:]

    if url[-1:] != '/':
        url = url + '/'

    domain = url[:url.index('/')]
    path = url[url.index('/'):]

    if path[-1:] != '/':
        path += '/'

    apps_map = app_map(raw=True)

    if domain not in domain_list(auth)['domains']:
        raise MoulinetteError(errno.EINVAL, m18n.n('domain_unknown'))

    if domain in apps_map:
        if path in apps_map[domain]:
            raise MoulinetteError(errno.EINVAL, m18n.n('app_location_already_used'))
        for app_path, v in apps_map[domain].items():
            if app_path in path and app_path.count('/') < path.count('/'):
                raise MoulinetteError(errno.EPERM,
                                      m18n.n('app_location_install_failed'))

    if app is not None:
        app_setting(app, 'domain', value=domain)
        app_setting(app, 'path', value=path)


def app_initdb(user, password=None, db=None, sql=None):
    """
    Create database and initialize it with optionnal attached script

    Keyword argument:
        db -- DB name (user unless set)
        user -- Name of the DB user
        password -- Password of the DB (generated unless set)
        sql -- Initial SQL file

    """
    if db is None:
        db = user

    return_pwd = False
    if password is None:
        password = random_password(12)
        return_pwd = True

    mysql_root_pwd = open('/etc/yunohost/mysql').read().rstrip()
    mysql_command = 'mysql -u root -p%s -e "CREATE DATABASE %s ; GRANT ALL PRIVILEGES ON %s.* TO \'%s\'@localhost IDENTIFIED BY \'%s\';"' % (mysql_root_pwd, db, db, user, password)
    if os.system(mysql_command) != 0:
        raise MoulinetteError(errno.EIO, m18n.n('mysql_db_creation_failed'))
    if sql is not None:
        if os.system('mysql -u %s -p%s %s < %s' % (user, password, db, sql)) != 0:
            raise MoulinetteError(errno.EIO, m18n.n('mysql_db_init_failed'))

    if return_pwd:
        return password

    msignals.display(m18n.n('mysql_db_initialized'), 'success')


def app_ssowatconf(auth):
    """
    Regenerate SSOwat configuration file


    """
    from yunohost.domain import domain_list
    from yunohost.user import user_list

    with open('/etc/yunohost/current_host', 'r') as f:
        main_domain = f.readline().rstrip()

    domains = domain_list(auth)['domains']

    users = {}
    for username in user_list(auth)['users'].keys():
        users[username] = app_map(user=username)

    skipped_urls = []
    skipped_regex = []
    unprotected_urls = []
    unprotected_regex = []
    protected_urls = []
    protected_regex = []
    redirected_regex = { main_domain +'/yunohost[\/]?$': 'https://'+ main_domain +'/yunohost/sso/' }
    redirected_urls ={}

    apps = {}
    try:
        apps_list = app_list()['apps']
    except:
        apps_list = []

    def _get_setting(settings, name):
        s = settings.get(name, None)
        return s.split(',') if s else []

    for app in apps_list:
        if _is_installed(app['id']):
            with open('{0}/{1}/settings.yml'.format(
                    apps_setting_path, app['id'])) as f:
                app_settings = yaml.load(f)
                for item in _get_setting(app_settings, 'skipped_uris'):
                    if item[-1:] == '/':
                        item = item[:-1]
                    skipped_urls.append(app_settings['domain'] + app_settings['path'][:-1] + item)
                for item in _get_setting(app_settings, 'skipped_regex'):
                    skipped_regex.append(item)
                for item in _get_setting(app_settings, 'unprotected_uris'):
                    if item[-1:] == '/':
                        item = item[:-1]
                    unprotected_urls.append(app_settings['domain'] + app_settings['path'][:-1] + item)
                for item in _get_setting(app_settings, 'unprotected_regex'):
                    unprotected_regex.append(item)
                for item in _get_setting(app_settings, 'protected_uris'):
                    if item[-1:] == '/':
                        item = item[:-1]
                    protected_urls.append(app_settings['domain'] + app_settings['path'][:-1] + item)
                for item in _get_setting(app_settings, 'protected_regex'):
                    protected_regex.append(item)
                if 'redirected_urls' in app_settings:
                    redirected_urls.update(app_settings['redirected_urls'])
                if 'redirected_regex' in app_settings:
                    redirected_regex.update(app_settings['redirected_regex'])

    for domain in domains:
        skipped_urls.extend(['/yunohost/admin', '/yunohost/api'])

    conf_dict = {
        'portal_domain': main_domain,
        'portal_path': '/yunohost/sso/',
        'additional_headers': {
            'Auth-User': 'uid',
            'Remote-User': 'uid',
            'Name': 'cn',
            'Email': 'mail'
        },
        'domains': domains,
        'skipped_urls': skipped_urls,
        'unprotected_urls': unprotected_urls,
        'protected_urls': protected_urls,
        'skipped_regex': skipped_regex,
        'unprotected_regex': unprotected_regex,
        'protected_regex': protected_regex,
        'redirected_urls': redirected_urls,
        'redirected_regex': redirected_regex,
        'users': users,
    }

    with open('/etc/ssowat/conf.json', 'w+') as f:
        json.dump(conf_dict, f, sort_keys=True, indent=4)

    msignals.display(m18n.n('ssowat_conf_generated'), 'success')


# Private classes and methods ------------------------------------------

class Application(object):
    """Application representation
 
    Provide access to an application information - given by its manifest - and
    settings if it's installed. It can be retrieved and instantiated by
    different constructors which will take care of initialize the object.

    Keyword arguments:
        - manifest -- A dict containing the app manifest
        - app_id -- The application id
        - remote -- Remote settings of the app
        - undefined_value -- The value to use for undefined properties

    """
    def __init__(self, manifest, app_id=None, remote=None,
            undefined_value='-'):
        self._manifest = manifest
        self._id = app_id if app_id else self.get_manifest_key(
            'id', required=True)
        if remote and isinstance(remote, dict):
            self._remote = remote
        self.undefined_value = undefined_value

    @classmethod
    def from_manifest_file(cls, path, **kwargs):
        """Construct the application from its JSON manifest file"""
        if 'manifest' in kwargs:
            raise ValueError('manifest argument not allowed, \
                it will be overridden.')
        with open(path, 'r') as f:
            manifest = json.load(f, 'utf-8')
        return cls(manifest, **kwargs)

    @classmethod
    def from_app_id(cls, app_id):
        """Retrieve and construct the application from its id"""
        data = (_get_lists_content(concatenate=True)).get(app_id)
        if data is None:
            raise ValueError("application id not found in lists")
        return cls(data['manifest'], app_id=app_id, remote=data.get('git'))

    @classmethod
    def from_installed_app(cls, app_id):
        """Retrieve and construct the application from an installed one"""
        try:
            return cls.from_manifest_file(
                '{0}/{1}/manifest.json'.format(apps_setting_path, app_id),
                app_id=app_id)
        except IOError:
            raise ValueError("application id not found in installed ones")

    @classmethod
    def all_in_list(cls, list_name):
        """Retrieve and construct applications for each entry in a list"""
        ret = {}
        apps = _get_lists_content([list_name], concatenate=True)
        for i, d in apps.items():
            ret[i] = cls(d['manifest'], app_id=i, remote=d.get('git'))
        return ret


    ## Manifest properties

    GLOBAL_INFO_PROPERTIES = [
        'name', 'description', 'url', 'version', 'categories',
    ]

    @property
    def id(self):
        """The unique application identifier"""
        return self._id

    @property
    def name(self):
        """The application name"""
        try:
            return self._name
        except AttributeError:
            self._name = self.get_manifest_key(
                'name', required=True)
            return self._name

    @property
    def description(self):
        """The application description in current locale"""
        try:
            return _value_for_locale(self._description)
        except AttributeError:
            self._description = self.get_manifest_key(
                'description', required=True)
            return self.description

    @property
    def version(self):
        """The upstream application version (optional)"""
        try:
            return self._version
        except AttributeError:
            self._version = self.get_manifest_key(
                'version', self.undefined_value)
            return self._version

    @property
    def url(self):
        """The upstream application URL (optional)"""
        try:
            return self._url
        except AttributeError:
            self._url = self.get_manifest_key(
                'url', self.undefined_value)
            return self._url

    @property
    def maintainer(self):
        """A dict with the application maintainer information"""
        try:
            return self._maintainer
        except AttributeError:
            info = self.get_manifest_key(
                'maintainer', required=True, deprecated=['developer'])
            self._maintainer = {
                'name': info.get('name', self.undefined_value),
                'email': info.get('email', self.undefined_value),
            }
            return self._maintainer

    @property
    def categories(self):
        """A list of categories that define the application (optional)"""
        try:
            return self._categories
        except AttributeError:
            self._categories = self.get_manifest_key(
                'categories', [])
            return self._categories

    @property
    def multi_instance(self):
        """Either the application can be installed multiple times or not"""
        try:
            return self._multi_instance
        except AttributeError:
            self._multi_instance = self.get_manifest_key(
                'multi_instance', False)
            return self._multi_instance

    @property
    def arguments(self):
        """A dict of arguments that the application need for the scripts"""
        try:
            return self._arguments
        except AttributeError:
            self._arguments = self.get_manifest_key(
                'arguments', {})
            return self._arguments


    ## Accessibility methods and properties

    @property
    def manifest(self):
        """Return the raw manifest"""
        return self._manifest

    @property
    def is_installed(self):
        """Either the application is installed or not"""
        if os.path.isdir('{0}/{1}'.format(apps_setting_path, self.id)):
            return True
        return False

    @property
    def settings(self):
        """Return the application settings if it's installed"""
        try:
            with open('{0}/{1}/settings.yml'.format(
                    apps_setting_path, self.id)) as f:
                return yaml.load(f)
        except:
            return {}

    def __repr__(self):
        """Representation of an application"""
        if self.multi_instance:
            return "<Application {0} - {1}>".format(self.name, self.id)
        else:
            return "<Application {0}>".format(self.name)

    def get_manifest_key(self, key, default=None, required=False,
            deprecated=[]):
        """Get a key value from the manifest

        Attempt to retrieve the value for 'key' from the manifest. The first
        founded value for keys in 'deprecated' will be returned if 'key' is
        not found.
        If default is not given and required is False, it defaults to None.
        Otherwise, a KeyError will be raised if key is not found.

        Keyword arguments:
            - key -- The key to get
            - default -- The default value to return if key is not found
            - required -- True to raise an exception if key is not found
            - deprecated -- A list of deprecated keys

        """
        try:
            return self._manifest[key]
        except KeyError:
            pass
        for k in deprecated:
            try:
                value = self._manifest[k]
            except KeyError:
                continue
            else:
                logger.warning("manifest's key '%s' is deprecated, " \
                    "please use '%s' instead", k, key)
                return value
        if default is None and required:
            raise KeyError("requied key '%s' is undefined" % key)
        return default

    def get_global_info(self, exclude=[], exclude_undefined=False):
        """Get global application informations

        Return global application informations as a dict. Properties in the
        'exclude' list will be skipped. If exclude_undefined is True,
        undefined keys will not be returned too.

        Keyword arguments:
            - exclude -- A collection of keys to exclude
            - exclude_undefined -- True to skip undefined keys

        """
        ret = OrderedDict()

        # Retrieve keys to return
        if exclude:
            exclude = set(exclude)
            keys = [k for k in self.GLOBAL_INFO_PROPERTIES if k not in exclude]
        else:
            keys = self.GLOBAL_INFO_PROPERTIES

        # Construct the returned dict
        if exclude_undefined:
            undefined_value = self.undefined_value
            self.undefined_value = None
            for k in keys:
                v = getattr(self, k)
                if v is not None:
                    ret[k] = v
            self.undefined_value = undefined_value
        else:
            ret = OrderedDict((k, getattr(self, k)) for k in keys)
        return ret


def _get_lists_content(lists=[], concatenate=False):
    """Retrieve the content of applications lists

    Keyword arguments:
        - lists -- A list of lists to retrieve (all by default)
        - concatenate -- True to concatenate the content of each list

    """
    # TODO: Provide this method into an action
    ret = {}
    if not lists:
        lists = app_listlists()['lists']
    if concatenate:
        _add = lambda l,c: ret.update(c)
    else:
        _add = lambda l,c: ret.update({l:c})

    for l in lists:
        try:
            with open('{0}/{1}.json'.format(repo_path, l)) as f:
                content = json.load(f, 'utf-8')
        except IOError:
            logger.warning("unknown list '%s'", l)
        else:
            _add(l, content)
    return ret


def _extract_app_from_file(path, remove=False):
    """
    Unzip or untar application tarball in app_tmp_folder, or copy it from a directory

    Keyword arguments:
        path -- Path of the tarball or directory
        remove -- Remove the tarball after extraction

    Returns:
        Dict manifest

    """
    global app_tmp_folder

    msignals.display(m18n.n('extracting'))

    if os.path.exists(app_tmp_folder): shutil.rmtree(app_tmp_folder)
    os.makedirs(app_tmp_folder)

    if ".zip" in path:
        extract_result = os.system('cd %s && unzip %s -d %s > /dev/null 2>&1' % (os.getcwd(), path, app_tmp_folder))
        if remove: os.remove(path)
    elif ".tar" in path:
        extract_result = os.system('cd %s && tar -xf %s -C %s > /dev/null 2>&1' % (os.getcwd(), path, app_tmp_folder))
        if remove: os.remove(path)
    elif (path[:1] == '/' and os.path.exists(path)) or (os.system('cd %s/%s' % (os.getcwd(), path)) == 0):
        shutil.rmtree(app_tmp_folder)
        if path[len(path)-1:] != '/':
            path += '/'
        extract_result = os.system('cd %s && cp -a "%s" %s' % (os.getcwd(), path, app_tmp_folder))
    else:
        extract_result = 1

    if extract_result != 0:
        raise MoulinetteError(errno.EINVAL, m18n.n('app_extraction_failed'))

    try:
        if len(os.listdir(app_tmp_folder)) == 1:
            for folder in os.listdir(app_tmp_folder):
                app_tmp_folder = app_tmp_folder +'/'+ folder
        with open(app_tmp_folder + '/manifest.json') as json_manifest:
            manifest = json.loads(str(json_manifest.read()))
            manifest['lastUpdate'] = int(time.time())
    except IOError:
        raise MoulinetteError(errno.EIO, m18n.n('app_install_files_invalid'))

    msignals.display(m18n.n('done'))

    return manifest


def _fetch_app_from_git(app):
    """
    Unzip or untar application tarball in app_tmp_folder

    Keyword arguments:
        app -- App_id or git repo URL

    Returns:
        Dict manifest

    """
    global app_tmp_folder

    msignals.display(m18n.n('downloading'))

    if ('@' in app) or ('http://' in app) or ('https://' in app):
        if "github.com" in app:
            url = app.replace("git@github.com:", "https://github.com/")
            if ".git" in url[-4:]: url = url[:-4]
            if "/" in url [-1:]: url = url[:-1]
            url = url + "/archive/master.zip"
            if os.system('wget "%s" -O "%s.zip" > /dev/null 2>&1' % (url, app_tmp_folder)) == 0:
                return _extract_app_from_file(app_tmp_folder +'.zip', remove=True)

        git_result   = os.system('git clone %s %s' % (app, app_tmp_folder))
        git_result_2 = 0
        try:
            with open(app_tmp_folder + '/manifest.json') as json_manifest:
                manifest = json.loads(str(json_manifest.read()))
                manifest['lastUpdate'] = int(time.time())
        except IOError:
            raise MoulinetteError(errno.EIO, m18n.n('app_manifest_invalid'))

    else:
        app_dict = app_list(raw=True)

        if app in app_dict:
            app_info = app_dict[app]
            app_info['manifest']['lastUpdate'] = app_info['lastUpdate']
            manifest = app_info['manifest']
        else:
            raise MoulinetteError(errno.EINVAL, m18n.n('app_unknown'))

        if "github.com" in app_info['git']['url']:
            url = app_info['git']['url'].replace("git@github.com:", "https://github.com/")
            if ".git" in url[-4:]: url = url[:-4]
            if "/" in url [-1:]: url = url[:-1]
            url = url + "/archive/"+ str(app_info['git']['revision']) + ".zip"
            if os.system('wget "%s" -O "%s.zip" > /dev/null 2>&1' % (url, app_tmp_folder)) == 0:
                return _extract_app_from_file(app_tmp_folder +'.zip', remove=True)

        app_tmp_folder = install_tmp +'/'+ app
        if os.path.exists(app_tmp_folder): shutil.rmtree(app_tmp_folder)

        git_result   = os.system('git clone %s -b %s %s' % (app_info['git']['url'], app_info['git']['branch'], app_tmp_folder))
        git_result_2 = os.system('cd %s && git reset --hard %s' % (app_tmp_folder, str(app_info['git']['revision'])))

    if not git_result == git_result_2 == 0:
        raise MoulinetteError(errno.EIO, m18n.n('app_sources_fetch_failed'))

    msignals.display(m18n.n('done'))

    return manifest


def _installed_instance_number(app, last=False):
    """
    Check if application is installed and return instance number

    Keyword arguments:
        app -- id of App to check
        last -- Return only last instance number

    Returns:
        Number of last installed instance | List or instances

    """
    if last:
        number = 0
        try:
            installed_apps = os.listdir(apps_setting_path)
        except OSError:
            os.makedirs(apps_setting_path)
            return 0

        for installed_app in installed_apps:
            if number == 0 and app == installed_app:
                number = 1
            elif '__' in installed_app:
                if app == installed_app[:installed_app.index('__')]:
                    if int(installed_app[installed_app.index('__') + 2:]) > number:
                        number = int(installed_app[installed_app.index('__') + 2:])

        return number

    else:
        instance_number_list = []
        instances_dict = app_map(app=app, raw=True)
        for key, domain in instances_dict.items():
            for key, path in domain.items():
                instance_number_list.append(path['instance'])

        return sorted(instance_number_list)


def _is_installed(app):
    """
    Check if application is installed

    Keyword arguments:
        app -- id of App to check

    Returns:
        Boolean

    """
    try:
        installed_apps = os.listdir(apps_setting_path)
    except OSError:
        os.makedirs(apps_setting_path)
        return False

    for installed_app in installed_apps:
        if app == installed_app:
            return True
        else:
            continue

    return False


def _value_for_locale(values):
    """
    Return proper value for current locale

    Keyword arguments:
        values -- A dict of values associated to their locale

    Returns:
        An utf-8 encoded string

    """
    if not isinstance(values, dict):
        return values

    for lang in [m18n.locale, m18n.default_locale]:
        try:
            return _encode_string(values[lang])
        except KeyError:
            continue

    # Fallback to first value
    return _encode_string(values.values()[0])


def _encode_string(value):
    """
    Return the string encoded in utf-8 if needed
    """
    if isinstance(value, unicode):
        return value.encode('utf8')
    return value


def is_true(arg):
    """
    Convert a string into a boolean

    Keyword arguments:
        arg -- The string to convert

    Returns:
        Boolean

    """
    true_list = ['yes', 'Yes', 'true', 'True' ]
    for string in true_list:
        if arg == string:
            return True
    return False


def random_password(length=8):
    """
    Generate a random string

    Keyword arguments:
        length -- The string length to generate

    """
    import string, random

    char_set = string.ascii_uppercase + string.digits + string.ascii_lowercase
    return ''.join(random.sample(char_set, length))
