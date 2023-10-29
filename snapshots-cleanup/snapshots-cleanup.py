#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
A python script that delete snapshots in error or older than specified age
"""
import sys
sys.path.append('/opt/symphony-client')

__version__ = "1.0.0"

import atexit
import os
import logging
import argparse
import requests
import getpass
import time
import json
import shutil
try:
    import subprocess32 as subprocess
except:
    import subprocess
from collections import defaultdict, OrderedDict
from datetime import datetime, timedelta
import dateutil.parser

from munch import Munch, unmunchify

import symphony_client

LOGS_DIR = "."
DATA_PATH_PREFIX = '{}/strato-remote-snapshots/v1/'
SNAPSHOT_CLEANUP_LOGS_DIR = LOGS_DIR + "/snapshots-cleanup-logs"
LOGGER_NAME = "snapshots-cleanup"
VPSA_VOLUME_TEMPLATE = 'neokarm_volume-{}'
VPSA_MIRROR_JOB_TEMPLATE = 'neokarm_mirror_{}'
VPSA_MIRROR_VOLUME_TEMPLATE = 'neokarm_mrr_vol_{}'
ZADARA_POOL_TYPE = 'Zadara VPSA (iSCSI)'
VPSA_LIST_LIMIT = 10000
MAX_VPSA_REQUEST_LOOPS = 10
DEFAULT_DST_CC_URL_PREFIX_TEMPLATE = "https://{host}:8888/clouds/{cloud}/vpsas/{vsa}/pt"
SLEEP_BEFORE_NEXT_OP=2
VALID_OPS = [
    'snapshots-status',
    'clean-snapshots-in-error',
    'purge-auto-snapshots',
    'purge-manual-snapshots',
    'purge-all-snapshots',
    'remote-metadata-status',
    'purge-remote-metadata',
]
ALL_EXTERNAL_ENDPOINTS = 'all_external_endpoints'
ALL_VMS = 'all_vms'
ALL_VOLUMES = 'all_volumes'
IMAGE_SNAPSHOTS = 'image_snapshots'
OLD_VOLUME_SNAPSHOTS = 'old_volume_snapshots'
OLD_AUTO_VOLUME_SNAPSHOTS = "old_auto_volume_snapshots"
OLD_MANUAL_VOLUME_SNAPSHOTS = "old_manual_volume_snapshots"
ERROR_VOLUME_SNAPSHOTS = 'error_volume_snapshots'
CREATING_VOLUME_SNAPSHOTS = 'creating_volume_snapshots'
OLD_VM_SNAPSHOTS = 'old_vm_snapshots'
OLD_AUTO_VM_SNAPSHOTS = "old_auto_vm_snapshots"
OLD_MANUAL_VM_SNAPSHOTS = "old_manual_vm_snapshots"
ERROR_VM_SNAPSHOTS = 'error_vm_snapshots'
CREATING_VM_SNAPSHOTS = 'creating_vm_snapshots'
PROTECTED_VOLUMES = 'protected_volumes'
PROTECTED_VM_SNAPSHOTS = 'protected_vm_snapshots'
PROTECTED_VOLUME_SNAPSHOTS = 'protected_volume_snapshots'
PROTECTED_VOLUME_SNAPSHOTS_PGS = 'protected_volume_snapshots_pgs'
PROTECTED_VM_SNAPSHOTS_PGS = 'protected_vm_snapshots_pgs'
ALL_VM_SNAPSHOTS = "all_vm_snapshots"
ALL_VOLUME_SNAPSHOTS = "all_volume_snapshots"
ALL_VM_REMOTE_SNAPSHOTS = 'all_vm_remote_snapshots'
ALL_VOLUME_REMOTE_SNAPSHOTS = 'all_volume_remote_snapshots'
METADATA_REMOTE_SNAPSHOTS = 'metadata_remote_snapshots'
METADATA_REMOTE_VM_SNAPSHOTS = 'metadata_remote_vm_snapshots'
METADATA_REMOTE_VOLUME_SNAPSHOTS = 'metadata_remote_volume_snapshots'
METADATA_REMOTE_NOTYPE_SNAPSHOTS = 'metadata_remote_notype_snapshots'
DELETED_METADATA_REMOTE_SNAPSHOTS = 'deleted_metadata_remote_snapshots'
DELETED_METADATA_EXIST_LOCAL_REMOTE_SNAPSHOTS = 'deleted_metadata_exist_local_remote_snapshots'
DELETED_METADATA_NO_LOCAL_REMOTE_SNAPSHOTS = 'deleted_metadata_no_local_remote_snapshots'
LIVE_METADATA_REMOTE_SNAPSHOTS = 'live_metadata_remote_snapshots'
LIVE_METADATA_REMOTE_WITH_LOCAL = 'live_metadata_remote_with_local'
LIVE_METADATA_REMOTE_WITH_LOCAL_API = 'live_metadata_remote_with_local_api'
LIVE_METADATA_REMOTE_WITH_LOCAL_API_READY = 'live_metadata_remote_with_local_api_ready'
LIVE_METADATA_REMOTE_WITH_LOCAL_API_ERROR = 'live_metadata_remote_with_local_api_error'
LIVE_METADATA_REMOTE_WITH_LOCAL_API_OTHER = 'live_metadata_remote_with_local_api_other'
LIVE_METADATA_REMOTE_NO_LOCAL_API = 'live_metadata_remote_no_local_api'
LOCAL_API_WITH_LIVE_METADATA_REMOTE = 'local_api_with_live_metadata_remote'
READY_LOCAL_API_WITH_LIVE_METADATA_REMOTE = 'ready_local_api_with_live_metadata_remote'
READY_LOCAL_API_WITH_NO_LIVE_METADATA_REMOTE = 'ready_local_api_with_no_live_metadata_remote'
ALL_VOLUME_REMOTE_SNAPSHOTS_BY_LOCAL_SNAPSHOT_ID = 'all_volume_remote_snapshots_by_local_snapshot_id'
LOCAL_SNAPSHOT_ID_WITHOUT_REMOTE_SNAPSHOT_ID = "local_snapshot_id_without_remote_snapshot_id"
LABEL_DICT = OrderedDict()
LABEL_DICT[ALL_VMS] = "VMs"
LABEL_DICT[ALL_VOLUMES] = "Volumes"
LABEL_DICT[ALL_VM_SNAPSHOTS] = "VM snapshots"
LABEL_DICT[ALL_VOLUME_SNAPSHOTS] = "Volume snapshots"
LABEL_DICT[ALL_VM_REMOTE_SNAPSHOTS] = "VM remote snapshots"
LABEL_DICT[ALL_VOLUME_REMOTE_SNAPSHOTS] = "Volume remote snapshots"
LABEL_DICT[PROTECTED_VOLUMES] = "Volumes to protect from retention"
LABEL_DICT[IMAGE_SNAPSHOTS] = "Image snapshots"
LABEL_DICT[ERROR_VOLUME_SNAPSHOTS] = "Volume snapshots in error/error-creating state"
LABEL_DICT[CREATING_VOLUME_SNAPSHOTS] = "Volume snapshots in error creating state"
LABEL_DICT[ERROR_VM_SNAPSHOTS] = "VM snapshots in error/error-creating state"
LABEL_DICT[CREATING_VM_SNAPSHOTS] = "VM snapshots in error creating state"
LABEL_DICT[PROTECTED_VM_SNAPSHOTS] = "VM Snapshots that will not be deleted because of protection"
LABEL_DICT[PROTECTED_VOLUME_SNAPSHOTS] = "Volume Snapshots that will not be deleted because of protection"
LABEL_DICT[PROTECTED_VOLUME_SNAPSHOTS_PGS] = "Volumes Snapshots to protect from retention due to triggering PG"
LABEL_DICT[PROTECTED_VM_SNAPSHOTS_PGS] = "VM Snapshots to protect from retention due to triggering PG"
LABEL_DICT[OLD_VOLUME_SNAPSHOTS] = "Volume snapshots older than retention time"
LABEL_DICT[OLD_AUTO_VOLUME_SNAPSHOTS] = "Automatic Volume snapshots older than retention time"
LABEL_DICT[OLD_MANUAL_VOLUME_SNAPSHOTS] = "Manual Volume snapshots older than retention time"
LABEL_DICT[OLD_VM_SNAPSHOTS] = "VM Snapshots older than retention time"
LABEL_DICT[OLD_AUTO_VM_SNAPSHOTS] = "Automatic VM Snapshots older than retention time"
LABEL_DICT[OLD_MANUAL_VM_SNAPSHOTS] = "Manual VM Snapshots older than retention time"
LABEL_DICT[METADATA_REMOTE_SNAPSHOTS] = "Remote snapshots metadata"
LABEL_DICT[DELETED_METADATA_REMOTE_SNAPSHOTS] = "Deleted remote snapshot metadata"
LABEL_DICT[DELETED_METADATA_EXIST_LOCAL_REMOTE_SNAPSHOTS] = "Deleted remote snapshot metadata with existing local API remote-snapshot"
LABEL_DICT[DELETED_METADATA_NO_LOCAL_REMOTE_SNAPSHOTS] = "Deleted remote snapshot metadata without existing local API remote-snapshot"
LABEL_DICT[METADATA_REMOTE_VM_SNAPSHOTS] = "Remote VM snapshot metadata"
LABEL_DICT[METADATA_REMOTE_VOLUME_SNAPSHOTS] = "Remote Volume snapshot metadata"
LABEL_DICT[METADATA_REMOTE_NOTYPE_SNAPSHOTS] = "Remote snapshot metadata with unknown type"
LABEL_DICT[LIVE_METADATA_REMOTE_SNAPSHOTS] = "Live remote snapshot metadata"
LABEL_DICT[LIVE_METADATA_REMOTE_WITH_LOCAL_API] = "Live remote snapshot metadata with local API"
LABEL_DICT[LIVE_METADATA_REMOTE_WITH_LOCAL_API_READY] = "Live remote snapshot metadata with local API state ready"
LABEL_DICT[LIVE_METADATA_REMOTE_WITH_LOCAL_API_ERROR] = "Live remote snapshot metadata with local API state error"
LABEL_DICT[LIVE_METADATA_REMOTE_WITH_LOCAL_API_OTHER] = "Live remote snapshot metadata with local API state unknown"
LABEL_DICT[LIVE_METADATA_REMOTE_NO_LOCAL_API] = "Live remote snapshot metadata with no local API object"
LABEL_DICT[LOCAL_API_WITH_LIVE_METADATA_REMOTE] = "Local API remote snapshot with live object"
LABEL_DICT[READY_LOCAL_API_WITH_LIVE_METADATA_REMOTE] = 'Ready Local API remote snapshot with live remote metadata'
LABEL_DICT[READY_LOCAL_API_WITH_NO_LIVE_METADATA_REMOTE] = 'Ready Local API remote snapshot without live remote metadata'
LABEL_DICT[ALL_VOLUME_REMOTE_SNAPSHOTS_BY_LOCAL_SNAPSHOT_ID] = "All volume remote snapshots keyed by local_snapshot_id"
LABEL_DICT[LOCAL_SNAPSHOT_ID_WITHOUT_REMOTE_SNAPSHOT_ID] = "Local snapshots without remote snapshot (or deleted)"
LABEL_DICT[ALL_EXTERNAL_ENDPOINTS] = "External endpoints"
logger = logging.getLogger()

vpsa_requesters_cache = dict()
symp_client_cache = dict()


def init_logger():
    formatter = logging.Formatter('%(asctime)s [%(name)s] %(levelname)-10s %(message)s')
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)

    if not os.path.exists(SNAPSHOT_CLEANUP_LOGS_DIR):
        os.makedirs(SNAPSHOT_CLEANUP_LOGS_DIR)

    logfile = '{logger_name}-{date}.log'.format(logger_name=LOGGER_NAME, date=datetime.now().strftime("%Y-%m-%d-%H%M"))
    logfile_with_path = os.path.join(SNAPSHOT_CLEANUP_LOGS_DIR, logfile)

    file_handler = logging.FileHandler(filename=logfile_with_path)
    atexit.register(file_handler.close)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)-10s %(message)s \t'
                                                '(%(pathname)s:%(lineno)d)'))
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    logger.setLevel(logging.DEBUG)

    logger.info("Logger initialized")


class Config(object):
    SRC_CLUSTER_IP = os.environ.get("SRC_CLUSTER_IP", None)
    SRC_ACCOUNT = os.environ.get("SRC_ACCOUNT", None)
    SRC_PROJECT_NAME = os.environ.get("SRC_PROJECT_NAME", None)
    SRC_USERNAME = os.environ.get("SRC_USERNAME", None)
    SRC_PASSWORD = os.environ.get("SRC_PASSWORD", None)
    SRC_MFA_SECRET = os.environ.get("SRC_MFA_SECRET", None)
    SRC_TOKEN = os.environ.get("SRC_TOKEN", None)
    SRC_TRANSFER_PROJECT_ID = os.environ.get("SRC_TRANSFER_PROJECT_ID", None)

    CLUSTER_IP = os.environ.get("DST_CLUSTER_IP", None)
    LOGIN_ACCOUNT = os.environ.get("DST_LOGIN_ACCOUNT", None)
    LOGIN_PROJECT_NAME = os.environ.get("DST_LOGIN_PROJECT_NAME", None)
    LOGIN_USERNAME = os.environ.get("DST_LOGIN_USERNAME", None)
    LOGIN_PASSWORD = os.environ.get("DST_LOGIN_PASSWORD", None)
    MFA_SECRET = os.environ.get("DST_MFA_SECRET", None)
    POOL_ID = os.environ.get("DST_POOL_ID", None)
    TOKEN = os.environ.get("DST_TOKEN", None)

    CC_CLOUD_ID = os.environ.get("DST_CC_CLOUD_ID", None)
    CC_VPSA_ID = os.environ.get("DST_CC_VPSA_ID", None)
    CC_HOST = os.environ.get("DST_CC_HOST", None)
    CC_URL_PREFIX_TEMPLATE = os.environ.get("DST_CC_URL_PREFIX_TEMPLATE",
                                            "https://{host}:8888/clouds/{cloud}/vpsas/{vsa}/pt")
    VPSA_VERIFY_SSL = os.environ.get("DST_VPSA_VERIFY_SSL", False)


def init_symp_client(args):
    env_vars = [Config.CLUSTER_IP, Config.LOGIN_ACCOUNT, Config.LOGIN_USERNAME, Config.LOGIN_PROJECT_NAME]
    if None in env_vars:
        raise Exception("Not all mandatory environment variables are set\n"
                        "use --online-config to update interactively")

    my_session = requests.Session()
    my_session.verify = args.verify
    cluster_ip = Config.CLUSTER_IP
    account_name = Config.LOGIN_ACCOUNT
    username = Config.LOGIN_USERNAME
    project_name = Config.LOGIN_PROJECT_NAME
    cache_key = "{}.{}.{}.{}".format(cluster_ip,
                                     account_name,
                                     username,
                                     project_name)
    if symp_client_cache.get(cache_key):
        return symp_client_cache.get(cache_key)

    token = None
    if Config.TOKEN:
        token = Config.TOKEN
    if token:
        try:
            logger.info("Going to login to %s using token", Config.CLUSTER_IP)
            client = symphony_client.Client(url='https://%s' % cluster_ip, session=my_session, token=token)
            my_session.headers['X-Auth-Token'] = token
            user_details = client._identity.users.get_my_details()
            if user_details.current_project_name != project_name:
                logger.info("Project mismatch - (%s) != (%s)", project_name, user_details.current_project_name)
            symp_client_cache[cache_key] = client
            return client
        except requests.HTTPError as ex:
            if ex.response.status_code == 401:
                logger.info("Failed to login using provided token - login using password")

    mfa_totp = None
    if args.mfa:
        mfa_totp = raw_input("MFA code:")
    logger.info("Going to login to %s, account %s, project %s, user %s",
                cluster_ip,
                account_name,
                project_name,
                username)
    if Config.LOGIN_PASSWORD:
        password = Config.LOGIN_PASSWORD
    else:
        password = getpass.getpass("Password: ")
    client = symphony_client.Client(url='https://%s' % cluster_ip, session=my_session)
    client.login(domain=account_name,
                 username=username,
                 password=password,
                 project=project_name,
                 mfa_totp=mfa_totp,
                 mfa_secret=Config.MFA_SECRET)
    symp_client_cache[cache_key] = client
    return client


def _validate_vpsa_response(response):
    if response is None:
        logger.debug("Empty VPSA Response")
        return False
    if response.status_code != 200:
        logger.debug("Response code: %s", response.status_code)
        return False
    try:
        if response.json().get('response', {}).get('status', -1) != 0:
            logger.debug("Response code: 200 but response is: %s", response.text)
            return False
        return True
    except Exception:
        logger.debug("Failed to parse VPSA response body: %s", response.text)
        return False


def get_vpsa_params(client, pool_id):
    logger.info("Loading VPSAs Params")
    try:
        pool_info = client.melet.pools.get(pool_id)
    except requests.HTTPError as ex:
        if ex.response.status_code == 404:
            raise Exception("VPSA Pool %s not found" % pool_id)
        raise
    if pool_info.type == ZADARA_POOL_TYPE:
        vpsa_params = {'pool_id': pool_info.id,
                       'access_key': pool_info.properties.access_key,
                       'vpsa_host': pool_info.properties.vpsa_host,
                       'vpsa_port': pool_info.properties.vpsa_port,
                       'use_ssl': pool_info.properties.use_ssl,
                       'verify_ssl': pool_info.properties.verify_ssl}
    else:
        raise Exception("VPSA Pool %s not a VPSA pool" % pool_id)
    return vpsa_params


def get_vpsa_requester(args, client, pool_id):
    if vpsa_requesters_cache.get(pool_id):
        return vpsa_requesters_cache.get(pool_id)

    vpsa_params = get_vpsa_params(client, pool_id)
    session = requests.sessions.Session()
    session.headers = {'Content-Type': 'application/json', 'X-Access-Key': vpsa_params['access_key']}
    session.verify = Config.VPSA_VERIFY_SSL if Config.VPSA_VERIFY_SSL is not None else vpsa_params['verify_ssl']
    dry_run = args.dry_run
    if dry_run:
        logger.info("VPSA Requester loaded in dry run mode")
    else:
        logger.info("VPSA Requester is loaded")
    if args.use_cc_passthrough:
        url_prefix = Config.CC_URL_PREFIX_TEMPLATE.format(
            host=Config.CC_HOST,
            cloud=Config.CC_CLOUD_ID.replace('-', ''),
            vsa=Config.CC_VPSA_ID)
    else:
        scheme = 'https' if vpsa_params['use_ssl'] else 'http'
        vpsa_host = vpsa_params['vpsa_host']
        if vpsa_params['use_ssl'] and str(vpsa_params['vpsa_port']) == '443':
            port_str = ''
        elif not vpsa_params['use_ssl'] and str(vpsa_params['vpsa_port']) == '80':
            port_str = ''
        else:
            port_str = ':{}'.format(vpsa_params['vpsa_port'])
        url_prefix = '{scheme}://{vpsa_host}{port_str}'.format(
            scheme=scheme,
            vpsa_host=vpsa_host,
            port_str=port_str)

    def vpsa_request(method, url, **kwargs):
        full_url = '{url_prefix}{url}'.format(url_prefix=url_prefix, url=url)
        logger.debug("Requesting: %s %s", method, full_url)
        headers = kwargs.get('headers', {})
        headers["X-Access-Key"] = vpsa_params['access_key']
        headers["Content-Type"] = 'application/json'
        if dry_run and method not in ['GET', 'HEAD']:
            return None
        return session.request(method, full_url, **kwargs)

    vpsa_requesters_cache[pool_id] = vpsa_request
    return vpsa_request


def get_vpsa_volume_by_name(vpsa_requester, display_name, must_succeed=False):
    response = None
    for _ in xrange(MAX_VPSA_REQUEST_LOOPS):
        response = vpsa_requester('GET', '/api/volumes.json?display_name={name}'.format(name=display_name))
        if _validate_vpsa_response(response):
            count = response.json().get('response', {}).get('count', 0)
            if count > 0:
                break
        time.sleep(10)
    if not _validate_vpsa_response(response):
        msg = "Expected volume {name} not found after mirror job break".format(name=display_name)
        logger.error(msg)
        if must_succeed:
            raise Exception(msg)
        return None
    count = response.json().get('response', {}).get('count', 0)
    if count == 0:
        msg = "Expected volume {name} not found after mirror job break".format(name=display_name)
        logger.error(msg)
        if must_succeed:
            raise Exception(msg)
        return None
    elif count > 1:
        msg = "There are multiple volumes with name {name} after mirror job break".format(name=display_name)
        logger.error(msg)
        if must_succeed:
            raise Exception(msg)
    volume = response.json().get('response', {}).get('volumes')[0]
    return volume


def get_to_ipdb(drop_to_debugger):
    if drop_to_debugger:
        import ipdb
        ipdb.set_trace()


def are_you_sure(args):
    if not args.answer_yes:
        sure = raw_input("Are you sure [Y/n]:")
        if sure in ["Y", 'y']:
            return True
        return False
    return True


def load_config(args):
    logger.info("Loading config interactively")
    if Config.CLUSTER_IP is None:
        Config.CLUSTER_IP = raw_input("CLUSTER_IP:")
    login_account = raw_input("LOGIN_ACCOUNT [{}]:".format(Config.LOGIN_ACCOUNT))
    if login_account:
        Config.LOGIN_ACCOUNT = login_account
    login_project_name = raw_input("LOGIN_PROJECT_NAME [{}]:".format(Config.LOGIN_PROJECT_NAME))
    if login_project_name:
        Config.LOGIN_PROJECT_NAME = login_project_name
    login_username = raw_input("LOGIN_USERNAME [{}]:".format(Config.LOGIN_USERNAME))
    if login_username:
        Config.LOGIN_USERNAME = login_username
    mfa_secret = raw_input("MFA_SECRET [{}]:".format(Config.MFA_SECRET))
    if mfa_secret:
        Config.MFA_SECRET = mfa_secret
    login_password = getpass.getpass("LOGIN_PASSWORD []:")
    if login_password:
        Config.LOGIN_PASSWORD = login_password


def write_config(args):
    lines = list()
    if Config.SRC_CLUSTER_IP:
        lines.append('export SRC_CLUSTER_IP="%s"\n' % Config.SRC_CLUSTER_IP)
    if Config.SRC_ACCOUNT:
        lines.append('export SRC_ACCOUNT="%s"\n' % Config.SRC_ACCOUNT)
    if Config.SRC_PROJECT_NAME:
        lines.append('export SRC_PROJECT_NAME="%s"\n' % Config.SRC_PROJECT_NAME)
    if Config.SRC_USERNAME:
        lines.append('export SRC_USERNAME="%s"\n' % Config.SRC_USERNAME)
    if args.write_passwords:
        if Config.SRC_PASSWORD:
            lines.append('export SRC_PASSWORD="%s"\n' % Config.SRC_PASSWORD)
    if Config.SRC_MFA_SECRET:
        lines.append('export SRC_MFA_SECRET="%s"\n' % Config.SRC_MFA_SECRET)
    if Config.SRC_TRANSFER_PROJECT_ID:
        lines.append('export SRC_TRANSFER_PROJECT_ID="%s"\n' % Config.SRC_TRANSFER_PROJECT_ID)
    if Config.SRC_TOKEN:
        lines.append('export SRC_TOKEN="%s"\n' % Config.SRC_TOKEN)

    if Config.CLUSTER_IP:
        lines.append('export DST_CLUSTER_IP="%s"\n' % Config.CLUSTER_IP)
    if Config.LOGIN_ACCOUNT:
        lines.append('export DST_LOGIN_ACCOUNT="%s"\n' % Config.LOGIN_ACCOUNT)
    if Config.LOGIN_PROJECT_NAME:
        lines.append('export DST_LOGIN_PROJECT_NAME="%s"\n' % Config.LOGIN_PROJECT_NAME)
    if Config.LOGIN_USERNAME:
        lines.append('export DST_LOGIN_USERNAME="%s"\n' % Config.LOGIN_USERNAME)
    if args.write_passwords:
        if Config.LOGIN_PASSWORD:
            lines.append('export DST_LOGIN_PASSWORD="%s"\n' % Config.LOGIN_PASSWORD)
    if Config.MFA_SECRET:
        lines.append('export DST_MFA_SECRET="%s"\n' % Config.MFA_SECRET)
    if Config.POOL_ID:
        lines.append('export DST_POOL_ID="%s"\n' % Config.POOL_ID)
    if Config.TOKEN:
        lines.append('export DST_TOKEN="%s"\n' % Config.TOKEN)

    if Config.CC_CLOUD_ID:
        lines.append('export CC_CLOUD_ID="%s"\n' % Config.CC_CLOUD_ID)
    if Config.CC_VPSA_ID:
        lines.append('export CC_VPSA_ID="%s"\n' % Config.CC_VPSA_ID)
    if Config.CC_HOST:
        lines.append('export CC_HOST="%s"\n' % Config.CC_HOST)
    if Config.CC_URL_PREFIX_TEMPLATE != DEFAULT_DST_CC_URL_PREFIX_TEMPLATE:
        lines.append('export CC_URL_PREFIX_TEMPLATE="%s"\n' % Config.CC_URL_PREFIX_TEMPLATE)
    if Config.VPSA_VERIFY_SSL:
        lines.append('export VPSA_VERIFY_SSL="%s"\n' % Config.VPSA_VERIFY_SSL)
    with open('cred_env', 'w') as f:
        f.writelines(lines)

    return True


def snapshots_status(args, client):
    get_to_ipdb(args.ipdb)
    results = defaultdict(OrderedDict)
    vms_ids_to_protect = args.protect_vms
    excluded_pg_ids_set = set(args.excluded_pgs)
    results[ALL_VMS] = OrderedDict({vm.id: vm.id for vm in client.vms.list()})
    results[ALL_VOLUMES] = OrderedDict({volume.id: volume.id for volume in client.meletvolumes.list()})
    volume_snapshots = client.snapshots.list()
    vm_snapshots = client.vm_snapshots.list()
    results[ALL_VM_REMOTE_SNAPSHOTS] = OrderedDict({rvs.id: rvs for rvs in client.remote_vm_snapshots.list()})
    results[ALL_VOLUME_REMOTE_SNAPSHOTS] = OrderedDict({rs.id: rs for rs in client.remote_snapshots.list()})
    results[ALL_VOLUME_REMOTE_SNAPSHOTS_BY_LOCAL_SNAPSHOT_ID] = OrderedDict({rs.snapshot_id: rs for rs in client.remote_snapshots.list()})
    vms_to_protect = {}
    if vms_ids_to_protect:
        vms_to_protect = {vm.id: vm for vm in client.vms.list(id=vms_ids_to_protect)}
    for vm in vms_to_protect.values():
        results[PROTECTED_VOLUMES][vm.bootVolume] = vm.bootVolume
        for volume in vm.volumes:
            results[PROTECTED_VOLUMES][volume] = volume
    for volume in args.protect_volumes:
        results[PROTECTED_VOLUMES][volume] = volume
    retention_day = datetime.now() - timedelta(days=args.retention_days)
    yesterday = datetime.now() - timedelta(days=1)
    logger.info("Considering snapshot older than %s for retention", retention_day.strftime("%c"))
    protected_volumes_set = set(results[PROTECTED_VOLUMES])
    protected_vms_set = set(vms_ids_to_protect)
    for snapshot in volume_snapshots:
        results[ALL_VOLUME_SNAPSHOTS][snapshot.id] = snapshot
        if snapshot.references and snapshot.references[0].resource_type == 'machine-image':
            results[IMAGE_SNAPSHOTS][snapshot.id] = snapshot
            continue
        if snapshot.source_volume_id in protected_volumes_set:
            results[PROTECTED_VOLUME_SNAPSHOTS][snapshot.id] = snapshot
            continue
        if snapshot.protection_group_id in excluded_pg_ids_set:
            results[PROTECTED_VOLUME_SNAPSHOTS][snapshot.id] = snapshot
            results[PROTECTED_VOLUME_SNAPSHOTS_PGS][snapshot.id] = snapshot
            continue
        datets = snapshot.created_at
        if datets[-1] == 'Z':
            datets = datets[:-1]
        snapshot_time = dateutil.parser.parse(datets)
        if snapshot_time < retention_day:
            results[OLD_VOLUME_SNAPSHOTS][snapshot.id] = snapshot
            if snapshot.protection_group_id:
                results[OLD_AUTO_VOLUME_SNAPSHOTS][snapshot.id] = snapshot
            else:
                results[OLD_MANUAL_VOLUME_SNAPSHOTS][snapshot.id] = snapshot
        if snapshot.state == 'error':
            results[ERROR_VOLUME_SNAPSHOTS][snapshot.id] = snapshot
        if snapshot.state == 'creating' and snapshot_time < yesterday:
            results[ERROR_VOLUME_SNAPSHOTS][snapshot.id] = snapshot
            results[CREATING_VOLUME_SNAPSHOTS][snapshot.id] = snapshot
    for snapshot in vm_snapshots:
        results[ALL_VM_SNAPSHOTS][snapshot.id] = snapshot
        if snapshot.source_vm_id in protected_vms_set:
            results[PROTECTED_VM_SNAPSHOTS][snapshot.id] = snapshot
            continue
        if snapshot.protection_group_id in excluded_pg_ids_set:
            results[PROTECTED_VM_SNAPSHOTS][snapshot.id] = snapshot
            results[PROTECTED_VM_SNAPSHOTS_PGS][snapshot.id] = snapshot
            continue
        datets = snapshot.created_at
        if datets[-1] == 'Z':
            datets = datets[:-1]
        snapshot_time = dateutil.parser.parse(datets)
        if snapshot_time < retention_day:
            results[OLD_VM_SNAPSHOTS][snapshot.id] = snapshot
            if snapshot.protection_group_id:
                results[OLD_AUTO_VM_SNAPSHOTS][snapshot.id] = snapshot
            else:
                results[OLD_MANUAL_VM_SNAPSHOTS][snapshot.id] = snapshot
        if snapshot.status == 'error':
            results[ERROR_VM_SNAPSHOTS][snapshot.id] = snapshot
        if snapshot.status == 'creating' and snapshot_time < yesterday:
            results[ERROR_VM_SNAPSHOTS][snapshot.id] = snapshot
            results[CREATING_VM_SNAPSHOTS][snapshot.id] = snapshot
    return results


def clean_vm_snapshots(args, client, label, vm_snapshots, all_vms):
    if args.only_volumes:
        return
    logger.info(label)
    get_to_ipdb(args.ipdb)
    if not are_you_sure(args):
        logger.info("User requested to skip")
        return
    for snapshot in vm_snapshots.values():
        logger.info(
            "Going to delete VM snapshot %s of VM %s/%s (%s)",
            snapshot.id,
            snapshot.source_vm_name,
            snapshot.source_vm_id,
            'exists' if all_vms.get(snapshot.source_vm_id) else 'deleted'
        )
        if not args.dry_run:
            try:
                client.vm_snapshots.delete(snapshot.id)
            except Exception as ex:
                logger.error("Failed to delete VM snapshot %s: %s", snapshot, ex)
                if args.break_on_error:
                    raise
        else:
            logger.info("Skipping")
        time.sleep(SLEEP_BEFORE_NEXT_OP)


def clean_volume_snapshots(args, client, label, volume_snapshots, all_volumes):
    if args.only_vms:
        return
    logger.info(label)
    get_to_ipdb(args.ipdb)
    if not are_you_sure(args):
        logger.info("User requested to skip")
        return
    for snapshot in volume_snapshots.values():
        logger.info(
            "Going to delete volume snapshot %s of volume %s (%s)",
            snapshot.id,
            snapshot.source_volume_id,
            'exists' if all_volumes.get(snapshot.source_volume_id) else 'deleted'
        )
        if not args.dry_run:
            try:
                client.snapshots.delete(snapshot.id)
            except Exception as ex:
                logger.error("Failed to delete volume snapshot %s: %s", snapshot, ex)
                if args.break_on_error:
                    raise
        else:
            logger.info("Skipping")
        time.sleep(SLEEP_BEFORE_NEXT_OP)


def print_snapshots_status(status_dict):
    for key, label in LABEL_DICT.items():
        logger.info("There are %s %s", len(status_dict[key]), label)


def print_all_snapshots(status_dict):
    for key, result in status_dict.items():
        logger.info("%s (%s):\n%s", LABEL_DICT[key], len(result), json.dumps(unmunchify(result), indent=2))


def _is_mounted(vpsa_nfs_share):
    df_output = subprocess.check_output(['df'])
    mounts = df_output.split('\n')
    mounts = [mount.split(' ') for mount in mounts]
    vpsa_nfs_share = vpsa_nfs_share
    external_endpoint_mount = [mount for mount in mounts
                               if mount and (mount[0] == vpsa_nfs_share or mount[-1] == vpsa_nfs_share)]
    return bool(external_endpoint_mount)


def _mount_vpsa_nfs_share(vpsa_nfs_share, mount_point):
    logger.info("mounting %s", vpsa_nfs_share)
    rc = subprocess.check_call(['mount', '-t', 'nfs', vpsa_nfs_share, mount_point])
    if rc != 0:
        logger.error("Failed to mount %s, please check NFS mount status", vpsa_nfs_share)
        sys.exit(1)
    logger.info("%s mounted successfully on %s", vpsa_nfs_share, mount_point)


def _unmount_vpsa_nfs_share(vpsa_nfs_share):
    logger.info("unmounting %s", vpsa_nfs_share)
    if _is_mounted(vpsa_nfs_share):
        rc = subprocess.check_call(['umount', vpsa_nfs_share])
        if rc != 0:
            logger.error("Failed to unmount %s, please un mount it manually", vpsa_nfs_share)
        else:
            logger.info("%s unmounted successfully", vpsa_nfs_share)
    else:
        logger.info("%s not mounted", vpsa_nfs_share)


def _load_metadata_json_file(path):
    meta_file_path = '{}/{}'.format(path, 'meta')
    try:
        with open(meta_file_path, 'r') as f:
            return json.load(f)
    except Exception as ex:
        logger.error("Failed to load json file from %s: %s", meta_file_path, ex)
    return None


def _mount_vpsa_external_endpoint(client, external_endpoint_id):
    # 'e5f4ccfc-e0fb-4dee-9374-9e3fce6353f4'
    # first check that the external-endpoint exists and in the correct type
    external_endpoint = client.externalendpoints.get(external_endpoint_id)
    if external_endpoint.endpoint_type != 'vpsa_backup':
        msg = "External endpoint {} ({}) is not of type vpsa_backup".format(external_endpoint.name, external_endpoint.id)
        logger.error(msg)
        sys.exit(msg)
    # check that mount point does not exist

    vpsa_nfs_share = external_endpoint.details.vpsa_nfs_share
    if _is_mounted(vpsa_nfs_share):
        msg = "External endpoint mount point {} already mounted - cannot continue without unmount".format(vpsa_nfs_share)
        logger.error(msg)
        sys.exit(msg)
    # mount
    cwd = os.getcwd()
    mount_point = '{}/{}'.format(cwd, external_endpoint_id)
    try:
        os.makedirs(mount_point)
    except OSError as ex:
        # ignore if mount-point already exists
        if ex.errno != 17:
            raise
    # Mount VPSA NFS share
    _mount_vpsa_nfs_share(vpsa_nfs_share, mount_point)
    # make sure it is un-mount on exit (install atexit handler)
    atexit.register(_unmount_vpsa_nfs_share, mount_point)
    return mount_point


def add_remote_metadata_status_for_external_endpoint(args, client, label, status_dict, external_endpoint_id):
    logger.info(label)
    get_to_ipdb(args.ipdb)
    mount_point = _mount_vpsa_external_endpoint(client, external_endpoint_id)
    data_prefix = DATA_PATH_PREFIX.format(mount_point)
    # list all snapshots metadata from mount
    file_count = 0
    count = 0
    for root, dir_names, file_names in os.walk(mount_point):
        file_count += 1
        if file_count % 1000 == 0:
            logger.info("Processed %s snapshot metadata", count)
        if 'meta' in file_names:
            count += 1
            # prevent recursion
            del dir_names[:]
            # get snapshot info
            # path format is:
            #  strato-remote-snapshots/v1/27cc63bcdea44bf393a2181e5386b5c5/8c9a2465-4466-4f51-b668-181b2eda1630/12F/6f0433d1-55e2-487a-ba02-3f57c34d8fce/7dd679fc-4c32-46fc-99b7-001f640e227d
            #  strato-remote-snapshots/v1/8be4559a157f4d5a9a3f0882b0916345/2c0599be-7173-4d2c-822d-3fc1c0a28dd6/2F/e31fc46f-98a1-4489-96fc-c25a4037f83e/8a5dada3-8a71-454d-82b0-642888b211e4
            #  strato-remote-snapshots/v1/
            #     <project-id>/<VM-ID\Volume-ID>/NA/<local-snapshot-id>/<remote-snapshot-id>/meta
            parts = root[len(data_prefix):].split('/')
            project_id = parts[0]
            entity_id = parts[1]
            local_volume_snapshot_id = parts[3]
            remote_volume_snapshot_id = parts[4]
            metadata = _load_metadata_json_file(root)
            deleted_attribute = '{}/v1/attribute/state/deleted'.format(root)
            try:
                os.stat(deleted_attribute)
                deleted = True
            except OSError as ex:
                deleted = False
            # Check if local volume snapshot exists
            local_volume_snapshot_exists = False
            if local_volume_snapshot_id in status_dict[ALL_VOLUME_SNAPSHOTS]:
                local_volume_snapshot_exists = True
            snapshot_type = 'no-local-entity'
            if entity_id in status_dict[ALL_VOLUMES]:
                snapshot_type = 'volume-snapshot'
            elif entity_id in status_dict[ALL_VMS]:
                snapshot_type = 'vm-snapshot'
            # Create metadata record
            remote_snapshot_data = {
                "project_id": project_id,
                "entity_id": entity_id,
                "external_endpoint_id": external_endpoint_id,
                "local_volume_snapshot_id": local_volume_snapshot_id,
                "remote_volume_snapshot_id": remote_volume_snapshot_id,
                "snapshot_type": snapshot_type,
                "metadata": metadata,
                "deleted": deleted,
                "local_volume_snapshot_exists": local_volume_snapshot_exists,
                "path": root
            }
            status_dict[METADATA_REMOTE_SNAPSHOTS][remote_volume_snapshot_id] = remote_snapshot_data
            if snapshot_type == 'no-local-entity':
                status_dict[METADATA_REMOTE_NOTYPE_SNAPSHOTS][remote_volume_snapshot_id] = remote_snapshot_data
            elif snapshot_type == 'volume-snapshot':
                status_dict[METADATA_REMOTE_VOLUME_SNAPSHOTS][remote_volume_snapshot_id] = remote_snapshot_data
            elif snapshot_type == 'vm-snapshot':
                status_dict[METADATA_REMOTE_VM_SNAPSHOTS][remote_volume_snapshot_id] = remote_snapshot_data

            if deleted:
                status_dict[DELETED_METADATA_REMOTE_SNAPSHOTS][remote_volume_snapshot_id] = remote_snapshot_data
                if local_volume_snapshot_exists:
                    status_dict[DELETED_METADATA_EXIST_LOCAL_REMOTE_SNAPSHOTS][remote_volume_snapshot_id] = remote_snapshot_data
                else:
                    status_dict[DELETED_METADATA_NO_LOCAL_REMOTE_SNAPSHOTS][remote_volume_snapshot_id] = remote_snapshot_data
            else:
                status_dict[LIVE_METADATA_REMOTE_SNAPSHOTS][remote_volume_snapshot_id] = remote_snapshot_data
                if local_volume_snapshot_exists:
                    status_dict[LIVE_METADATA_REMOTE_WITH_LOCAL][remote_volume_snapshot_id] = remote_snapshot_data
                api_remote_snapshot_obj = status_dict[ALL_VOLUME_REMOTE_SNAPSHOTS].get(remote_volume_snapshot_id)
                if api_remote_snapshot_obj:
                    status_dict[LIVE_METADATA_REMOTE_WITH_LOCAL_API][remote_volume_snapshot_id] = remote_snapshot_data
                    if api_remote_snapshot_obj.state == 'ready':
                        status_dict[LIVE_METADATA_REMOTE_WITH_LOCAL_API_READY][remote_volume_snapshot_id] = remote_snapshot_data
                    elif api_remote_snapshot_obj.state == 'error':
                        status_dict[LIVE_METADATA_REMOTE_WITH_LOCAL_API_ERROR][remote_volume_snapshot_id] = remote_snapshot_data
                    else:
                        status_dict[LIVE_METADATA_REMOTE_WITH_LOCAL_API_OTHER][remote_volume_snapshot_id] = remote_snapshot_data
                else:
                    status_dict[LIVE_METADATA_REMOTE_NO_LOCAL_API][remote_volume_snapshot_id] = remote_snapshot_data
            # check for missing metadata for remote_snapshots
    _unmount_vpsa_nfs_share(mount_point)
    for local_api_remote_snapshot in status_dict[ALL_VOLUME_REMOTE_SNAPSHOTS].values():
        if local_api_remote_snapshot.external_endpoint_id == external_endpoint_id:
            if local_api_remote_snapshot.state == 'ready':
                if local_api_remote_snapshot.id in status_dict[LIVE_METADATA_REMOTE_SNAPSHOTS].keys():
                    status_dict[READY_LOCAL_API_WITH_LIVE_METADATA_REMOTE][local_api_remote_snapshot.id] = local_api_remote_snapshot
                else:
                    status_dict[READY_LOCAL_API_WITH_NO_LIVE_METADATA_REMOTE][local_api_remote_snapshot.id] = local_api_remote_snapshot


def add_remote_metadata_status_for_all_vpsa_external_endpoint(args, client, label, status_dict):
    logger.info(label)
    external_endpoints = client.externalendpoints.list()
    status_dict[ALL_EXTERNAL_ENDPOINTS] = OrderedDict({ee.id: ee for ee in external_endpoints})
    for external_endpoint in external_endpoints:
        if external_endpoint.endpoint_type == 'vpsa_backup':
            label = "Analyzing remote metadata status for external endpoint: {} ({})".format(external_endpoint.id, external_endpoint.name)
            add_remote_metadata_status_for_external_endpoint(args, client, label, status_dict, external_endpoint.id)


def purge_remote_metadata_status_for_external_endpoint(args, client, label, status_dict, external_endpoint_id):
    logger.info(label)
    logger.info("Going to delete %s metadata objects for remote snapshots", len(status_dict[DELETED_METADATA_NO_LOCAL_REMOTE_SNAPSHOTS]))
    if not are_you_sure(args):
        sys.exit(0)
    mount_point = _mount_vpsa_external_endpoint(client, external_endpoint_id)
    count = 0
    total = len(status_dict[DELETED_METADATA_NO_LOCAL_REMOTE_SNAPSHOTS])
    for remote_metadata in status_dict[DELETED_METADATA_NO_LOCAL_REMOTE_SNAPSHOTS].values():
        if remote_metadata.get('external_endpoint_id') == external_endpoint_id:
            count += 1
            path = remote_metadata.get('path')
            if path:
                logger.info(
                    "Going to delete remote volume snapshot %s metadata (%s) (%s/%s):\n  %s",
                    remote_metadata.get('remote_volume_snapshot_id'),
                    external_endpoint_id,
                    count,
                    total,
                    path
                )
                if not args.dry_run:
                    shutil.rmtree(path)
                else:
                    logger.info("Skipping")
                time.sleep(0.01)
            else:
                logger.error(
                    "Missing path for remote volume snapshot %s metadata %s",
                    remote_metadata.get('remote_volume_snapshot_id'),
                    external_endpoint_id,
                    path
                )
    # need to add command to clean directories: find . -empty -type d -printf "removed '%p'\n" -delete
    data_prefix = DATA_PATH_PREFIX.format(mount_point)
    logger.info("deleting empty directories starting at %s", data_prefix)
    rc = subprocess.check_call(['find', data_prefix, '-empty', '-type', 'd', '-delete'])
    if rc != 0:
        logger.error("Failed to cleanup %s, please check NFS mount status", data_prefix)
    _unmount_vpsa_nfs_share(mount_point)


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "op",
        choices=VALID_OPS,
        help="Operation to perform. one of: "
             "migrate (migrate a VM), "
             "migrate_vpc_vms (migrate all user VMs in a VPC), "
             "migrate_all (migrate a list of VMs - from a filename), "
             "manage (manage a single volume), "
             "unmanage (unmanage a single volume)"
    )
    parser.add_argument("--no-dry-run", dest='dry_run', action='store_false',
                        help="Run in non dry run mode", required=False)
    parser.add_argument("--dry-run", dest='dry_run', action='store_true',
                        help="Run in dry run mode (Default)", required=False)
    parser.add_argument("-y", "--answer-yes", dest='answer_yes', action='store_true',
                        help="Automatically allow all operations", default=False, required=False)
    parser.add_argument("-k", "--no-verify-ssl", dest='verify', action='store_false',
                        help="Skip SSL connection verification", default=True, required=False)
    parser.set_defaults(dry_run=True)
    parser.add_argument("--print-all", action='store_true', help="Print all snapshots to the log",
                        required=False, default=False)
    parser.add_argument("--only-volumes", action='store_true', help="Perform only volume snapshots retention",
                        required=False, default=False)
    parser.add_argument("--only-vms", action='store_true', help="Perform only VM snapshots retention",
                        required=False, default=False)
    parser.add_argument("--protect-vm", action='append', help="VM IDs to protect from retention"
                                                              " (can appear multiple times)",
                        dest='protect_vms', default=list(), required=False)
    parser.add_argument("--exclude-pg", action='append', help="Protection group IDs to protect from retention"
                                                              " (can appear multiple times)",
                        dest='excluded_pgs', default=list(), required=False)
    parser.add_argument("--protect-volume", action='append', help="Volume IDs to protect from retention"
                                                                  " (can appear multiple times)",
                        dest='protect_volumes', default=list(), required=False)
    parser.add_argument("--continue-on-error", action='store_true', help="Continue on error",
                        dest='break_on_error', default=False, required=False)
    parser.add_argument("--ipdb", action='store_true', help="Drop to ipdb debugger before login",
                        default=False, required=False)
    parser.add_argument("--mfa", action='store_true', help="Ask for MFA code",
                        default=False, required=False)
    parser.add_argument('--online-config', help="Read login parameters interactively",
                        action='store_true', default=False, required=False)
    parser.add_argument('--temp-token', help="Do not write login token to env file",
                        action='store_true', default=False, required=False)
    parser.add_argument('--write-config', help="Write env file ('env' in local directory) with login parameters",
                        action='store_true', default=False, required=False)
    parser.add_argument('--overwrite-config', help="Overwrite env file ('env' in local directory) with login parameters",
                        action='store_true', default=False, required=False)
    parser.add_argument('--write-passwords', help="Write passwords to env file",
                        action='store_true', default=False, required=False)
    parser.add_argument('--retention-days', help="Number of days for retention period",
                        default=14, type=int, required=False)
    parser.add_argument("--external-endpoint", help="VPSA Type External endpoint ID to cleanup",
                        dest='external_endpoint', default='all', required=False)
    # Specify output of "--version"
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s (version {version})".format(version=__version__))
    return parser.parse_args()


def main():
    """ This is executed when run from the command line """
    args = parse_arguments()
    init_logger()
    get_to_ipdb(args.ipdb)

    if args.overwrite_config:
        args.write_config = True
    elif args.write_config:
        if os.path.exists('env'):
            msg = "File 'env' already exists in local directory, refusing to overwrite"
            logger.error(msg)
            sys.exit(msg)

    if args.online_config:
        load_config(args)

    client = init_symp_client(args)

    if args.write_config:
        if not args.temp_token:
            Config.TOKEN = client._session.headers['X-Auth-Token']
        write_config(args)

    # dst_client = init_dst_symp_client()
    # src_client = init_src_symp_client()
    # vpsa_requester = get_vpsa_requester(args, dst_client, Config.DST_POOL_ID)
    # get_vpsa_volume_by_name(vpsa_requester, VPSA_VOLUME_TEMPLATE.format(volume_id)

    status_dict = snapshots_status(args, client)
    all_vms = {vm.id: vm for vm in client.vms.list()}
    all_volumes = {volume.id: volume for volume in client.meletvolumes.list()}
    for vm_id in args.protect_vms:
        logger.info("Protecting VM %s/%s", vm_id, all_vms.get(vm_id, {}).get('name', 'unknown'))
    for volume_id in status_dict[PROTECTED_VOLUMES]:
        logger.info("Protecting volumes %s/%s", volume_id, all_volumes.get(volume_id, {}).get('name', 'unknown'))
    if args.op == 'snapshots-status':
        print_snapshots_status(status_dict)
        if args.print_all:
            print_all_snapshots(status_dict)
        sys.exit(0)
    if args.dry_run:
        logger.info("Running in dry-run mode")
    else:
        logger.info("Running in live mode - snapshots will be deleted")
        if not are_you_sure(args):
            sys.exit(0)

    if args.op == 'clean-snapshots-in-error':
        print_snapshots_status(status_dict)
        label = "Going to delete VM Snapshots in error: {}".format(len(status_dict[ERROR_VM_SNAPSHOTS]))
        clean_vm_snapshots(args, client, label, status_dict[ERROR_VM_SNAPSHOTS], all_vms)
        label = "Going to delete Volume Snapshots in error: {}".format(len(status_dict[ERROR_VOLUME_SNAPSHOTS]))
        clean_volume_snapshots(args, client, label, status_dict[ERROR_VOLUME_SNAPSHOTS], all_volumes)
        sys.exit(0)
    elif args.op == 'purge-auto-snapshots':
        print_snapshots_status(status_dict)
        label = "Going to delete Auto generated VM Snapshots older than {} days: {}".format(
            args.retention_days, len(status_dict[OLD_AUTO_VM_SNAPSHOTS])
        )
        clean_vm_snapshots(args, client, label, status_dict[OLD_AUTO_VM_SNAPSHOTS], all_vms)
        label = "Going to delete Auto generated Volume Snapshots older than {} days: {}".format(
            args.retention_days, len(status_dict[OLD_AUTO_VOLUME_SNAPSHOTS])
        )
        clean_volume_snapshots(args, client, label, status_dict[OLD_AUTO_VOLUME_SNAPSHOTS], all_volumes)
        sys.exit(0)
    elif args.op == 'purge-manual-snapshots':
        print_snapshots_status(status_dict)
        label = "Going to delete manual VM Snapshots older than {} days: {}".format(
            args.retention_days, len(status_dict[OLD_MANUAL_VM_SNAPSHOTS])
        )
        clean_vm_snapshots(args, client, label, status_dict[OLD_MANUAL_VM_SNAPSHOTS], all_vms)
        label = "Going to delete manual Volume Snapshots older than {} days: {}".format(
            args.retention_days, len(status_dict[OLD_MANUAL_VOLUME_SNAPSHOTS])
        )
        clean_volume_snapshots(args, client, label, status_dict[OLD_MANUAL_VOLUME_SNAPSHOTS], all_volumes)
        sys.exit(0)
    elif args.op == 'purge-all-snapshots':
        print_snapshots_status(status_dict)
        label = "Going to delete all VM Snapshots older than {} days: {}".format(
            args.retention_days, len(status_dict[OLD_VM_SNAPSHOTS])
        )
        clean_vm_snapshots(args, client, label, status_dict[OLD_VM_SNAPSHOTS], all_vms)
        label = "Going to delete all Volume Snapshots older than {} days: {}".format(
            args.retention_days, len(status_dict[OLD_VOLUME_SNAPSHOTS])
        )
        clean_volume_snapshots(args, client, label, status_dict[OLD_VOLUME_SNAPSHOTS], all_volumes)
        sys.exit(0)
    elif args.op == 'remote-metadata-status':
        if args.external_endpoint == 'all':
            label = "Analyzing remote metadata status for external endpoints"
            add_remote_metadata_status_for_all_vpsa_external_endpoint(args, client, label, status_dict)
        else:
            label = "Analyzing remote metadata status for external endpoint: {}".format(args.external_endpoint)
            add_remote_metadata_status_for_external_endpoint(args, client, label, status_dict, args.external_endpoint)
        print_snapshots_status(status_dict)
        sys.exit(0)
    elif args.op == 'purge-remote-metadata':
        if args.external_endpoint == 'all':
            label = "Analyzing remote metadata status for external endpoints"
            add_remote_metadata_status_for_all_vpsa_external_endpoint(args, client, label, status_dict)
            print_snapshots_status(status_dict)
        else:
            label = "Analyzing remote metadata status for external endpoint: {}".format(args.external_endpoint)
            add_remote_metadata_status_for_external_endpoint(args, client, label, status_dict, args.external_endpoint)
            print_snapshots_status(status_dict)
            label = "Purging remote metadata marked as deleted and without local API remote-snapshots"
            purge_remote_metadata_status_for_external_endpoint(args, client, label, status_dict, args.external_endpoint)
        sys.exit(0)
    else:
        logger.info("Please provide a valid op, one of:  %s", '/'.join(VALID_OPS))
        sys.exit("No valid op provided")


if __name__ == "__main__":
    main()
