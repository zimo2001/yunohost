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

""" yunohost_domain.py

    Manage domains
"""
import os
import sys
import datetime
import re
import shutil
import json
import yaml
import errno
from urllib import urlopen

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

logger = getActionLogger('yunohost.domain')

DOMAIN_SERVICES = ['web', 'mail', 'im']


def domain_list(auth, used_for=[], limit=None):
    """
    List domains

    Keyword argument:
        used_for -- Filter domains used only for those services
        limit -- Maximum number of domain fetched

    """
    result_list = []
    ldap_filter = '(virtualdomain=*)'

    # Validate and process arguments
    if limit is not None and limit == 0:
        limit = None
    if used_for:
        classes = _validate_domain_services(used_for)
        if len(classes) == 1:
            ldap_filter = '(objectClass={0:s})'.format(classes[0])
        else:
            ldap_filter = '(|(objectClass={0}){1})'.format(classes[0],
                ''.join('(|(objectClass={0}))'.format(s) for s in classes[1:])
            )

    result = auth.search(
        'ou=domains,dc=yunohost,dc=org', ldap_filter, ['virtualdomain'],
    )
    try:
        result_list = [d['virtualdomain'][0] for d in result[:limit]]
    except IndexError:
        pass
    return { 'domains': result_list }


def domain_info(auth, domain):
    """
    Get information about a domain

    Keyword arguments:
        domain -- Domain to get info from

    """
    result = auth.search(
        'ou=domains,dc=yunohost,dc=org',
        '(virtualdomain={0})'.format(domain),
        ['virtualdomain', 'virtualdomaindescription', 'objectClass'],
    )
    if not result:
        raise MoulinetteError(errno.EINVAL, m18n.n('domain_unknown'))

    info = {
        'domain': domain,
        'description': result[0].get('virtualdomaindescription', '-'),
    }

    # Check SSL certificate
    # TODO: add info about it
    info['certificate'] = os.path.isdir(
            '/etc/yunohost/certs/{0}'.format(domain))

    # Retrieve services for which domain is used
    info['used_for'] = [
        # remove 'Domain' suffix from objectClass
        s[:-6] for s in result[0]['objectClass'] if (
            'Domain' in s and s != 'virtualDomain'
        )
    ]
    # Check if object is still using old LDAP schema
    if 'virtualDomain' not in result[0]['objectClass']:
        info['old_schema'] = True

    # TODO: add info about DynDNS
    return info


def domain_add(auth, domain, dyndns=False, use_for=[]):
    """
    Add a domain

    Keyword argument:
        domain -- Domain to add
        dyndns -- Subscribe to DynDNS
        use_for -- Services to use domain for (all by default)

    """
    from yunohost.service import service_regenconf
    from yunohost.hook import hook_callback

    # Validate arguments
    if not use_for:
        use_for = DOMAIN_SERVICES
    elif not isinstance(use_for, list):
        use_for = [use_for,]
    add_services = set(use_for)

    # Attempt to retrieve domain info
    try:
        info = domain_info(auth, domain)
    except MoulinetteError:
        info = None
    else:
        if not info['used_for']:
            raise MoulinetteError(errno.EINVAL, m18n.n('domain_exists'))
        for s in use_for:
            if s in info['used_for']:
                logger.warning(m18n.n('domain_service_exists', service=s))
                add_services.remove(s)
        if not add_services:
            return

    # Subscribe to DynDNS
    if dyndns:
        import requests
        from yunohost.dyndns import dyndns_subscribe

        # Split and validate domain parts
        domain_parts = domain.split('.', maxsplit=1)
        if len(domain_parts) != 2 or '.' not in domain_parts[1]:
            raise MoulinetteError(errno.EINVAL,
                m18n.n('domain_dyndns_invalid'))

        # TODO: Make a stronger check
        if os.path.exists('/etc/cron.d/yunohost-dyndns'):
            raise MoulinetteError(errno.EPERM,
                m18n.n('domain_dyndns_already_subscribed'))

        try:
            r = requests.get('https://dyndns.yunohost.org/domains')
        except ConnectionError:
            raise MoulinetteError(errno.EIO,
                m18n.n('domain_dyndns_connection_error'))
        else:
            dyndomains = json.loads(r.text)
            if domain_parts[1] in dyndomains:
                dyndns_subscribe(domain=domain)
            else:
                raise MoulinetteError(errno.EINVAL,
                    m18n.n('domain_dyndns_root_unknown',
                        dyndomains=dyndomains))

    # Retrieve LDAP object classes for given services
    services = set(add_services)
    if info and info['used_for']:
        services.update(info['used_for'])
    classes = _validate_domain_services(services)
    classes.append('virtualDomain')

    # Add domain in LDAP
    # TODO: Allow a description through virtualdomaindescription
    # TODO: Is 'top' in objectClass needed?
    attr_dict = {
        'objectClass': classes,
        'virtualdomain': domain,
    }
    try:
        rdn_domain = 'virtualdomain={0},ou=domains'.format(domain)
        if info:
            if 'old_schema' in info:
                auth.remove(rdn_domain)
                auth.add(rdn_domain, attr_dict)
            else:
                auth.update(rdn_domain, attr_dict)
        else:
            auth.add(rdn_domain, attr_dict)
    except MoulinetteError:
        raise MoulinetteError(errno.EIO, m18n.n('domain_creation_failed'))

    if info and not info['certificate']:
        try:
            ip = str(urlopen('http://ip.yunohost.org').read())
        except IOError:
            ip = "127.0.0.1"
        now = datetime.datetime.now()
        timestamp = str(now.year) + str(now.month) + str(now.day)

        # Commands
        ssl_dir = '/usr/share/yunohost/yunohost-config/ssl/yunoCA'
        ssl_domain_path  = '/etc/yunohost/certs/%s' % domain
        with open('%s/serial' % ssl_dir, 'r') as f:
            serial = f.readline().rstrip()
        try: os.listdir(ssl_domain_path)
        except OSError: os.makedirs(ssl_domain_path)

        command_list = [
            'cp %s/openssl.cnf %s'                               % (ssl_dir, ssl_domain_path),
            'sed -i "s/yunohost.org/%s/g" %s/openssl.cnf'        % (domain, ssl_domain_path),
            'openssl req -new -config %s/openssl.cnf -days 3650 -out %s/certs/yunohost_csr.pem -keyout %s/certs/yunohost_key.pem -nodes -batch'
            % (ssl_domain_path, ssl_dir, ssl_dir),
            'openssl ca -config %s/openssl.cnf -days 3650 -in %s/certs/yunohost_csr.pem -out %s/certs/yunohost_crt.pem -batch'
            % (ssl_domain_path, ssl_dir, ssl_dir),
            'ln -s /etc/ssl/certs/ca-yunohost_crt.pem %s/ca.pem' % ssl_domain_path,
            'cp %s/certs/yunohost_key.pem    %s/key.pem'         % (ssl_dir, ssl_domain_path),
            'cp %s/newcerts/%s.pem %s/crt.pem'                   % (ssl_dir, serial, ssl_domain_path),
            'chmod 755 %s'                                       % ssl_domain_path,
            'chmod 640 %s/key.pem'                               % ssl_domain_path,
            'chmod 640 %s/crt.pem'                               % ssl_domain_path,
            'chmod 600 %s/openssl.cnf'                           % ssl_domain_path,
            'chown root:metronome %s/key.pem'                    % ssl_domain_path,
            'chown root:metronome %s/crt.pem'                    % ssl_domain_path,
            'cat %s/ca.pem >> %s/crt.pem'                        % (ssl_domain_path, ssl_domain_path)
        ]

        for command in command_list:
            if os.system(command) != 0:
                try:
                    # TODO: Remove only the certificate
                    domain_remove(auth, domain, True)
                except:
                    pass
                raise MoulinetteError(errno.EIO,
                                      m18n.n('domain_cert_gen_failed'))

    # Regenerate configurations
    if os.path.isfile('/etc/yunohost/installed'):
        if 'web' in add_services:
            from yunohost.app import app_ssowatconf
            service_regenconf(service='nginx')
            service_regenconf(service='dnsmasq')
            app_ssowatconf(auth)
        if 'im' in add_services:
            service_regenconf(service='metronome')

    hook_callback('post_domain_add', args=[domain])

    if info is None:
        logger.success(m18n.n('domain_created'))
    else:
        logger.success(m18n.n('domain_service_added'))


def domain_remove(auth, domain, force=False, used_for=[]):
    """
    Remove a domain

    Keyword argument:
        domain -- Domain to remove
        force -- Force the domain removal
        used_for -- Remove domain only for those services

    """
    from yunohost.service import service_regenconf
    from yunohost.hook import hook_callback

    # Attempt to retrieve domain info
    try:
        info = domain_info(auth, domain)
    except MoulinetteError:
        if not force:
            raise MoulinetteError(errno.EINVAL, m18n.n('domain_unknown'))
        info = None

    # Validate and process arguments
    keep_services = None
    if used_for and info and used_for != info['used_for']:
        need_update = False
        keep_services = set(info['used_for'])
        for s in used_for:
            if s in keep_services:
                need_update = True
                keep_services.remove(s)
            else:
                logger.warning(m18n.n('domain_service_unknown', service=s))
        if not need_update:
            return
    else:
        used_for = DOMAIN_SERVICES

    # Check if apps are installed on the domain
    if not force and (not keep_services or 'web' not in keep_services):
        for app in os.listdir('/etc/yunohost/apps/'):
            # TODO: Use app_info instead
            with open('/etc/yunohost/apps/' + app +'/settings.yml') as f:
                try:
                    app_domain = yaml.load(f)['domain']
                except:
                    continue
                else:
                    if app_domain == domain:
                        raise MoulinetteError(errno.EPERM,
                            m18n.n('domain_uninstall_app_first'))

    # Process LDAP operation
    rdn_domain = 'virtualdomain={0},ou=domains'.format(domain)
    if not keep_services:
        try:
            auth.remove(rdn_domain)
        except MoulinetteError:
            if not force:
                raise MoulinetteError(errno.EIO,
                    m18n.n('domain_deletion_failed'))
        # TODO: Replace os.system by subprocess
        os.system('rm -rf /etc/yunohost/certs/%s' % domain)
    else:
        classes = _validate_domain_services(keep_services)
        classes.append('virtualDomain')
        try:
            auth.update(rdn_domain, {'objectClass': classes})
        except MoulinetteError:
            raise MoulinetteError(errno.EIO, m18n.n('domain_update_failed'))

    if 'web' in used_for:
        from yunohost.app import app_ssowatconf
        service_regenconf(service='nginx')
        service_regenconf(service='dnsmasq')
        app_ssowatconf(auth)
    if 'im' in used_for:
        service_regenconf(service='metronome')

    hook_callback('post_domain_remove', args=[domain])

    if not keep_services:
        logger.success(m18n.n('domain_deleted'))
    else:
        logger.success(m18n.n('domain_service_deleted'))


# Helpers ---------------------------------------------------------------------

def _validate_domain_services(services, quiet=False):
    """Validate domain services and return relevant LDAP classes

    Keyword arguments:
        - services -- A list of domain services to validate
        - quiet -- Either an exception must be raised if a service
            is unknown or not

    """
    classes = []
    if isinstance(services, basestring):
        services = [services,]
    for s in services:
        if s not in DOMAIN_SERVICES:
            msg = m18n.n('domain_service_invalid', service=s)
            if not quiet:
                raise MoulinetteError(errno.EINVAL, msg)
            else:
                logger.warning(msg)
        else:
            classes.append('{0:s}Domain'.format(s))
    return classes
