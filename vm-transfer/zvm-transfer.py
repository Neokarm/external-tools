#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
A python script that clones a VM from the source system to the destination system
"""
import sys
sys.path.append('/opt/symphony-client')

__version__ = "0.1.0"

import os
import logging
import argparse
import atexit
import requests
import json
from pprint import pformat, pprint
from munch import Munch, unmunchify
from config import Config

import symphony_client

LOGS_DIR = "."
ZVM_CLONE_LOGS_DIR = LOGS_DIR + "/zvm-transfer-logs"
LOGGER_NAME = "zvm-transfer"
VPSA_VOLUME_TEMPLATE = 'neokarm_volume-{}'
VPSA_MIRROR_JOB_TEMPLATE = 'neokarm_mirror_{}'
VPSA_MIRROR_VOLUME_TEMPLATE = 'neokarm_mrr_vol_{}'
ZADARA_POOL_TYPE = 'Zadara VPSA (iSCSI)'
VPSA_LIST_LIMIT = 10000
MAX_VPSA_REQUEST_LOOPS = 10

logger = logging.getLogger(LOGGER_NAME)

arguments = None
vpsa_requesters_cache = dict()


def migrate_vm(vm_id_or_name, vpc_id=None):
    logger.info("vm_id: %s", vm_id_or_name)

    src_symp_client = init_src_symp_client()
    vm_list = src_symp_client.vms.list(detailed=True)
    vm = get_vm_by_id(src_symp_client, vm_id_or_name, vm_list)
    if not vm:
        vm = get_vm_by_name(src_symp_client, vm_id_or_name, vm_vpc_id=vpc_id, project_id=Config.SRC_TRANSFER_PROJECT_ID)
        if not vm:
            logger.error("VM %s is not found in source cluster", vm_id_or_name)
            sys.exit(1)
    _migrate_vm(vm)


def _migrate_vm(vm):
    vm_id = vm.id
    if vm.status not in ['stopped', 'shutoff']:
        if not arguments.ignore_vm_state:
            logger.error("VM {} ({}) is not in a valid state in source cluster: {}".format(vm.name, vm_id, vm.status))
            sys.exit(1)
        else:
            logger.warning("VM {} ({}) is not in a valid state in source cluster: {}"
                           " - user requested to ignore".format(vm.name, vm_id, vm.status))

    dst_symp_client = init_dst_symp_client()
    src_symp_client = init_src_symp_client()
    dest_vm = get_vm_by_name(dst_symp_client, vm.name, vm.vpc_id, project_id=Config.DST_TRANSFER_PROJECT_ID)
    if dest_vm:
        logger.info("VM {} ({}) already exists in destination".format(dest_vm.name, dest_vm.id))
        sys.exit(1)

    networks = create_networking_map(src_symp_client, dst_symp_client, vm)
    manageable_volumes, existing_volumes, mirror_jobs = check_volumes_in_dest(vm, dst_symp_client)

    create_new_vm(vm, networks, manageable_volumes, existing_volumes, mirror_jobs, dst_symp_client)

    logger.info("VM %s cloning is complete", vm.name)


def get_vm_by_id(client, vm_id, vm_list=None):
    if vm_list is None:
        vm_list = client.vms.list(detailed=True)
    filtered_vm_list = [vm for vm in vm_list if vm.id == vm_id]
    if not filtered_vm_list:
        logger.info("VM with id: %s does not exist", vm_id)
        return None
    return filtered_vm_list[0]


def get_vm_by_name(client, vm_name, vm_vpc_id=None, project_id=None, vm_list=None):
    if vm_list is None:
        vm_list = client.vms.list(detailed=True)
    filtered_vm_list = [vm for vm in vm_list
                        if vm.name == vm_name
                        and (vm_vpc_id is None or vm.vpc_id == vm_vpc_id)
                        and vm.project_id == project_id]
    if not filtered_vm_list:
        logger.info("VM with name: %s does not exists", vm_name)
        return None
    if len(filtered_vm_list) > 1:
        logger.info("There are mulitple VM with name: %s in this project - please provide VM uuid", vm_name)
        return None
    return filtered_vm_list[0]


def init_src_symp_client():
    my_session = requests.Session()
    my_session.verify = False
    client = symphony_client.Client(url='https://%s' % Config.SRC_CLUSTER_IP, session=my_session)
    client.login(domain=Config.SRC_ACCOUNT,
                 username=Config.SRC_USERNAME,
                 password=Config.SRC_PASSWORD,
                 project=Config.SRC_PROJECT_ID,
                 mfa_secret=Config.SRC_MFA_SECRET)
    return client


def init_dst_symp_client():
    my_session = requests.Session()
    my_session.verify = False
    client = symphony_client.Client(url='https://%s' % Config.DST_CLUSTER_IP, session=my_session)
    client.login(domain=Config.DST_ACCOUNT,
                 username=Config.DST_USERNAME,
                 password=Config.DST_PASSWORD,
                 project='default',
                 mfa_secret=Config.DST_MFA_SECRET)
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


def get_vpsa_requester(client, pool_id):
    if vpsa_requesters_cache.get(pool_id):
        return vpsa_requesters_cache.get(pool_id)

    vpsa_params = get_vpsa_params(client, pool_id)
    session = requests.sessions.Session()
    session.headers = {'Content-Type': 'application/json', 'X-Access-Key': vpsa_params['access_key']}
    session.verify = Config.DST_VPSA_VERIFY_SSL if Config.DST_VPSA_VERIFY_SSL is not None else vpsa_params['verify_ssl']
    dry_run = arguments.dry_run
    if dry_run:
        logger.info("VPSA Requester loaded in dry run mode")
    else:
        logger.info("VPSA Requester is loaded")
    if arguments.use_cc_passthrough:
        url_prefix = Config.DST_CC_URL_PREFIX_TEMPLATE.format(
            host=Config.DST_CC_HOST,
            cloud=Config.DST_CC_CLOUD_ID,
            vsa=Config.DST_CC_VPSA_ID)
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


def create_networking_map(src_client, dst_client, vm):
    src_networks = src_client.vpcs.networks.list(project_id=Config.SRC_TRANSFER_PROJECT_ID, vpc_id=vm.vpc_id)
    src_networks_id_to_name = {network.id: network.name for network in src_networks}
    if len(src_networks) != len(set([network.name for network in src_networks if network.name])):
        msg = "There are at least two networks with the same name (or without name) in the source: {}".format(
            [network['name'] for network in src_networks]
        )
        logger.info(msg)
        raise Exception(msg)
    dst_networks = dst_client.vpcs.networks.list(project_id=Config.DST_TRANSFER_PROJECT_ID)
    dst_networks_name_to_id = {network.name: network.id for network in dst_networks if network.name}
    if len(dst_networks) != len(dst_networks_name_to_id):
        msg = "There are at least two networks with the same name (or without name) in the destinations: {}".format(
            [network['name'] for network in dst_networks]
        )
        logger.info(msg)
        raise Exception(msg)

    all_security_group_names = set()
    networks = list()
    for port in vm.ports:
        source_network_name = src_networks_id_to_name.get(port.network_id)
        if source_network_name == '':
            msg = "Cowardly refusing to transfer VM from a network with an empty name. " \
                  "please make sure that source and destination networks has the same non-empty name"
            logger.info(msg)
            raise Exception(msg)
        if source_network_name is None:
            msg = "Didn't find network {} name in source".format(port.network_id)
            logger.info(msg)
            logger.info(pformat(src_networks_id_to_name))
            raise Exception(msg)
        dest_network_id = dst_networks_name_to_id.get(source_network_name)
        if dest_network_id is None:
            msg = "Didn't find matching network with name %s in destination" % source_network_name
            logger.info(msg)
            raise Exception(msg)
        security_group_names = [sg.name for sg in port.security_groups]

        network = {
            "net_id": dest_network_id,
            "ipv4": port.legacy_params.address,
            "mac": port.mac_address,
            "security_groups": security_group_names
        }
        all_security_group_names.update(security_group_names)
        existing_sg = dst_client.vpcs.security_groups.list(project_id=Config.DST_TRANSFER_PROJECT_ID, name=list(security_group_names))
        if len(existing_sg) != len(all_security_group_names):
            msg = "Didn't find matching security_groups in destination out of: %s" % all_security_group_names
            logger.info(msg)
            if arguments.skip_sg:
                network.pop('security_groups')
            else:
                raise Exception(msg)
        networks.append(network)
    return networks


def manage_single_volume(volume_id, volume_name, look_for_mirror=True):
    dst_client = init_dst_symp_client()
    manageable_volumes = dst_client.meletvolumes.list_manageable(Config.DST_POOL_ID)
    existing_volumes = [volume for volume in dst_client.meletvolumes.list() if volume.storagePool == Config.DST_POOL_ID]
    mirror_jobs = get_mirror_jobs_from_vpsa(dst_client, Config.DST_POOL_ID) if look_for_mirror else None
    manage_volume(dst_client, manageable_volumes, existing_volumes, mirror_jobs, volume_id, 0, volume_name=volume_name)


def unmanage_single_volume(volume_id):
    dst_client = init_dst_symp_client()
    volume_info = [volume for volume in dst_client.meletvolumes.list()
                   if volume.storagePool == Config.DST_POOL_ID and volume.id == volume_id]
    if volume_info:
        dst_client.meletvolumes.unmanage(volume_id)
    else:
        msg = "Didn't find matching matching volume %s in destination" % volume_id
        logger.info(msg)
        raise Exception(msg)


def manage_volumes_in_dest(vm, dst_client, manageable_volumes, existing_volumes, mirror_jobs):
    # Manage
    index = 0
    manage_volume(dst_client, manageable_volumes, existing_volumes, mirror_jobs, vm.bootVolume, index, vm)
    for volume in vm.volumes:
        index = index + 1
        manage_volume(dst_client, manageable_volumes, existing_volumes, mirror_jobs, volume, index, vm)


def get_existing_and_managable_volumes(client):
    manageable_volumes = client.meletvolumes.list_manageable(Config.DST_POOL_ID)
    existing_volumes = [volume for volume in client.meletvolumes.list() if volume.storagePool == Config.DST_POOL_ID]
    return existing_volumes, manageable_volumes


def check_volumes_in_dest(vm, dst_client, look_for_mirror=True):
    existing_volumes, manageable_volumes = get_existing_and_managable_volumes(dst_client)
    mirror_jobs = get_mirror_jobs_from_vpsa(dst_client, Config.DST_POOL_ID) if look_for_mirror else None

    # Check if volume manage is possible
    check_manage_volume(manageable_volumes, existing_volumes, mirror_jobs, vm.bootVolume)
    for volume in vm.volumes:
        check_manage_volume(manageable_volumes, existing_volumes, mirror_jobs, volume)
    return manageable_volumes, existing_volumes, mirror_jobs


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


def update_vpsa_volume_dedup_compression(client, vpsa_volume):
    logger.info("Updating volume %s (%s) to use dedup and compression", vpsa_volume['display_name'],
                vpsa_volume['name'])
    vpsa_requester = get_vpsa_requester(client, Config.DST_POOL_ID)
    api_data = json.dumps({'dedupe': 'YES', 'compress':'YES'})
    response = vpsa_requester('PUT', '/api/volumes/{id}.json'.format(id=vpsa_volume['name']),
                              data=api_data)
    if not _validate_vpsa_response(response):
        logger.warning("Failed to update dedup & compression for volume: %s (%s)",
                       vpsa_volume['display_name'], vpsa_volume['name'])


def break_mirror_and_refresh_volumes(client, mirror_job, volume_id):
    logger.info("Breaking mirror job: %s and renaming to %s", mirror_job['job_display_name'],
                VPSA_VOLUME_TEMPLATE.format(volume_id))
    expected_volume_name = mirror_job.get('dst', {}).get('cg_display_name')
    if not expected_volume_name:
        msg = "Expected volume name after break not found in mirror job"
        logger.error(msg)
        raise msg
    vpsa_requester = get_vpsa_requester(client, Config.DST_POOL_ID)
    logger.info("Breaking Mirror %s (%s)", mirror_job['job_display_name'], mirror_job['job_name'])
    response = vpsa_requester('POST', '/api/mirror_jobs/{id}/break.json'.format(id=mirror_job['job_name']))
    response.raise_for_status()
    volume = get_vpsa_volume_by_name(vpsa_requester, expected_volume_name, must_succeed=True)
    # update volume compression and dedupe
    update_vpsa_volume_dedup_compression(client, volume)
    return rename_mirror_job_volume_and_refresh_volumes(client, volume['display_name'], volume_id)


def rename_mirror_job_volume_and_refresh_volumes(client, vpsa_volume_display_name, volume_id):
    logger.info("Renaming vpsa volume display name: %s to %s", vpsa_volume_display_name, VPSA_VOLUME_TEMPLATE.format(volume_id))
    vpsa_requester = get_vpsa_requester(client, Config.DST_POOL_ID)
    response = vpsa_requester('GET', '/api/volumes.json?display_name={id}'.format(id=vpsa_volume_display_name))
    response.raise_for_status()
    if not _validate_vpsa_response(response):
        msg = "Expected volume {id} not found".format(id=vpsa_volume_display_name)
        logger.error(msg)
        raise Exception(msg)

    vpsa_volume_name = response.json().get('response', {}).get('volumes', [{}])[0].get('name')
    expected_volume_display_name = VPSA_VOLUME_TEMPLATE.format(volume_id)
    logger.info("Renaming Mirror job volume %s, display_name from %s to %s",
                vpsa_volume_name,
                vpsa_volume_display_name,
                expected_volume_display_name)
    api_data = json.dumps({"new_name": expected_volume_display_name})
    response = vpsa_requester('POST', '/api/volumes/{id}/rename.json'.format(id=vpsa_volume_name), data=api_data)
    if not _validate_vpsa_response(response):
        msg = "Volume {id}({name}) renaming failed".format(id=vpsa_volume_name, name=vpsa_volume_display_name)
        logger.error(msg)
        raise Exception(msg)
    volume = get_vpsa_volume_by_name(vpsa_requester, expected_volume_display_name, must_succeed=True)
    return get_existing_and_managable_volumes(client)


def manage_volume(client, manageable_volumes, existing_volumes, mirror_jobs, volume_id, index,
                  vm=None, ignore_exists=True, volume_name=None):
    if arguments.use_only_mirror_jobs:
        logger.info("Only using existing volumes or existing mirror jobs")
    volume_or_mirror_job = check_manage_volume(manageable_volumes, existing_volumes, mirror_jobs, volume_id, ignore_exists=ignore_exists)
    # Check if this is a mirror job
    if isinstance(volume_or_mirror_job, dict) and volume_or_mirror_job.get('job_display_name'):
        # This is a mirror job - need to break mirror
        mirror_job = volume_or_mirror_job
        existing_volumes, manageable_volumes = break_mirror_and_refresh_volumes(client, mirror_job, volume_id)
    elif isinstance(volume_or_mirror_job, Munch) and \
            volume_or_mirror_job.reference.name.startswith(VPSA_MIRROR_VOLUME_TEMPLATE.format(volume_id)):
        # This is a volume originated in a mirror job (job was broken - just rename volume
        volume_name = volume_or_mirror_job.reference.name
        existing_volumes, manageable_volumes = rename_mirror_job_volume_and_refresh_volumes(client,
                                                                                            volume_name,
                                                                                            volume_id)
    elif isinstance(volume_or_mirror_job, Munch) and volume.reference.name == VPSA_VOLUME_TEMPLATE.format(volume_id):
        vpsa_volume_id = volume_or_mirror_job.reference.name
        logger.info("Managing volume: %s", vpsa_volume_id)
    else:
        logger.info("Managing volume: %s", VPSA_VOLUME_TEMPLATE.format(volume_id))

    # Manage volume if not exists
    existing_vol = [v for v in existing_volumes if v.id == volume_id]
    if not existing_vol:
        if index > 0:
            name = "volume #{} for {}".format(index, vm.id) if vm else volume_name or "Volume {}".format(volume_id)
        elif index == 0:
            name = "bootVolume #{} for {}".format(index, vm.id) if vm else volume_name or "Volume {}".format(volume_id)
        else:
            raise Exception("Invalid volume index %s" % index)
        client.meletvolumes.manage(name=name,
                                   storage_pool=Config.DST_POOL_ID,
                                   reference={"name": VPSA_VOLUME_TEMPLATE.format(volume_id)},
                                   project_id=Config.DST_TRANSFER_PROJECT_ID,
                                   volume_id=volume_id)


def check_manage_volume(manageable_volumes, existing_volumes, mirror_jobs, volume_id,
                        ignore_exists=True):
    volume_to_manage = [volume for volume in manageable_volumes if
                        volume.reference.name == VPSA_VOLUME_TEMPLATE.format(volume_id)]
    if ignore_exists:
        existing_vol = [v for v in existing_volumes if v.id == volume_id]
        if existing_vol:
            logger.info("Requested volume %s already exists - skipping", volume_id)
            return None
    if volume_to_manage:
        logger.info("Found volume to manage = %s", volume_to_manage)
        volume_to_manage = volume_to_manage[0]
    elif mirror_jobs is not None:
        logger.info("No volume %s to manage - looking for a mirror job", VPSA_VOLUME_TEMPLATE.format(volume_id))
        volume_to_manage = [volume for volume in manageable_volumes if
                            volume.reference.name.startswith(VPSA_MIRROR_VOLUME_TEMPLATE.format(volume_id))]
        valid_mirror_jobs = [mirror_job for mirror_job in mirror_jobs if
                             mirror_job['job_display_name'].startswith(VPSA_MIRROR_JOB_TEMPLATE.format(volume_id))]
        if valid_mirror_jobs or arguments.use_only_mirror_jobs:
            if len(valid_mirror_jobs) == 1:
                msg = "Found a mirrored job for this volume = %s" % valid_mirror_jobs[0]['job_display_name']
                logger.info(msg)
                return valid_mirror_jobs[0]
            elif len(valid_mirror_jobs) > 1:
                msg = "Found multiple mirrored jobs for this volume = %s" % [mj['job_display_name'] for mj in valid_mirror_jobs]
                logger.info(msg)
                raise Exception(msg)
            else:
                msg = "Did not find any mirrored jobs for this volume = %s" % volume_id
                logger.info(msg)
                raise Exception(msg)
        else:
            logging.info("No mirrored job for volume %s looking for mirror volumes", volume_id)
            if volume_to_manage:
                msg = "Found a mirrored volume to manage = %s" % volume_to_manage[0].reference.name
                logger.info(msg)
                volume_to_manage = volume_to_manage[0]
                return volume_to_manage
    else:
        msg = "Did not find volume to manage = %s" % volume_id
        logger.info(msg)
        raise Exception(msg)

    if volume_to_manage.get('reason_not_safe') == 'Volume not available':
        msg = "volume %s is not yet available" % volume_id
        logger.info(msg)
        raise Exception(msg)
    elif volume_to_manage.get('reason_not_safe') == 'Volume already managed':
        if ignore_exists:
            msg = "volume %s already managed - skipping" % volume_id
            logger.info(msg)
            existing_vol = [v for v in existing_volumes if v.id == volume_id]
            if existing_vol:
                msg = "A volume with the same ID %s already exists in the pool - skipping" % volume_id
                logger.info(msg)
            else:
                msg = "Volume is managed in VPSA but no volume %s in the pool" % volume_id
                logger.info(msg)
                raise Exception(msg)
        else:
            msg = "volume %s already managed" % volume_id
            logger.info(msg)
            raise Exception(msg)
    elif not volume_to_manage.get('safe_to_manage', False):
        msg = "volume %s is not manageable" % volume_id
        logger.info(msg)
        raise Exception(msg)

    existing_vol = [v for v in existing_volumes if v.id == volume_id]
    if existing_vol:
        if not ignore_exists:
            msg = "A volume with the same ID %s already exists in the pool" % volume_id
            logger.info(msg)
            raise Exception(msg)
        else:
            msg = "A volume with the same ID %s already exists in the pool - skipping" % volume_id
            logger.info(msg)
            return volume_to_manage


def get_dst_project_id(src_project_id, src_client, dst_client):
    logger.info("Searching source cluster for project ID: %s", src_project_id)
    src_project = src_client.projects.get(src_project_id)
    project_name = src_project.name

    logger.info("Searching destination cluster for project name: %s", project_name)
    dst_projects_list = dst_client.projects.list(name=project_name)

    if len(dst_projects_list) == 0:
        raise Exception("The destination cluster does not contain a project with the name: %s", project_name)
    if len(dst_projects_list) > 1:
        raise Exception("The destination cluster contains more than one project with the name: %s", project_name)

    return dst_projects_list[0].id


def create_new_vm(vm, networks, manageable_volumes, existing_volumes, mirror_jobs, dst_client):
    filtered_tags = [tag for tag in vm.tags if not tag.startswith('system:')] or None
    guest_os = None
    if 'system:os_family_windows' in vm.tags:
        guest_os = 'windows'
    if vm.get('managing_resource', {}).get('resource_id'):
        logger.info("VM %s is a managed VM - skipping", pformat(vm.name))
        return

    vm_params = dict(name=vm.name,
                     instance_type=vm.instanceType,
                     project_id=Config.DST_TRANSFER_PROJECT_ID,
                     restart_on_failure=False,
                     tags=filtered_tags,
                     boot_volumes=[{"id": vm.bootVolume, "disk_bus": "virtio", "device_type": "disk"}],
                     volumes_to_attach=vm.volumes,
                     hw_firmware_type=vm.hw_firmware_type,
                     networks=networks,
                     guest_os=guest_os,
                     os_type_id=vm.provided_os_type_id,
                     powerup=False)
    logger.info("VM Creation params:\n%s", pformat(vm_params))
    if arguments.dry_run:
        logger.info("Dry run - not creating")
        return
    manage_volumes_in_dest(vm, dst_client, manageable_volumes, existing_volumes, mirror_jobs)

    created_vm = dst_client.vms.create(**vm_params)
    logger.info("Created VM:\n%s", pformat(created_vm))


def get_mirror_jobs_from_vpsa(client, pool_id):
    vpsa_requester = get_vpsa_requester(client, pool_id)
    mirror_jobs = list()
    start = 0
    for _ in range(MAX_VPSA_REQUEST_LOOPS):
        url = '/api/mirror_jobs.json?limit={limit}&start={start}'.format(limit=VPSA_LIST_LIMIT, start=start)
        response = vpsa_requester('GET', url)
        response.raise_for_status()
        count = response.json().get('response', {}).get('count', -1)
        request_mirror_jobs = response.json().get('response', {}).get('vpsa_mirror_jobs', [])
        mirror_jobs.extend(request_mirror_jobs)
        if count <= 0 or count <= start + VPSA_LIST_LIMIT:
            break
        start = start + VPSA_LIST_LIMIT
    return mirror_jobs


def init_logger(vm_id):
    formatter = logging.Formatter('%(asctime)s [%(name)s] %(levelname)-10s %(message)s')
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if not os.path.exists(ZVM_CLONE_LOGS_DIR):
        os.makedirs(ZVM_CLONE_LOGS_DIR)

    logfile = '{logger_name}-{vm_id}.log'.format(logger_name=LOGGER_NAME, vm_id=vm_id)
    logfile_with_path = os.path.join(ZVM_CLONE_LOGS_DIR, logfile)

    file_handler = logging.FileHandler(filename=logfile_with_path)
    atexit.register(file_handler.close)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)-10s %(message)s \t'
                                                '(%(pathname)s:%(lineno)d)'))
    logger.addHandler(file_handler)

    for handler in logger.handlers:
        handler.set_level = logging.DEBUG
    logger.setLevel(logging.DEBUG)

    logger.info("Logger initialized")


def migrate_vpc_vms(vpc_id):
    src_client = init_src_symp_client()
    vm_list = src_client.vms.list(detailed=True)
    filtered_vm_list = [vm for vm in vm_list
                        if vm.project_id == Config.SRC_TRANSFER_PROJECT_ID
                        and vm.vpc_id == vpc_id
                        and vm.managing_resource.resource_id is None]
    logger.info("The following VMs will be transferred:\n%s", pformat({vm.id: vm.name for vm in filtered_vm_list}))
    ans = raw_input("Continue [Y/n]? ")
    if ans != 'Y':
        sys.exit(1)
    for vm in filtered_vm_list:
        try:
            logger.info("migrate VM: %s %s", vm.name, vm.id)
            ans = raw_input("Continue [Y/n]? ")
            if ans == 'Y':
                _migrate_vm(vm)
        except Exception as exc:
            logger.exception("Failed to migrate VM: %s with error %s", vm.name, vm.id)
            ans = raw_input("Continue [Y/n]? ")
            if ans != 'Y':
                sys.exit(str(exc))


def get_to_ipdb():
    # dst_client = init_dst_symp_client()
    # src_client = init_src_symp_client()
    # vpsa_requester = get_vpsa_requester(dst_client, Config.DST_POOL_ID)
    import ipdb; ipdb.set_trace()


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("op", choices=['migrate', 'migrate_all', 'migrate_vpc_vms', 'manage', 'unmanage'],
                        help="Operation to perform. one of: "
                             "migrate (migrate a VM), "
                             "migrate_vpc_vms (migrate all user VMs in a VPC), "
                             "migrate_all (migrate a list of VMs - from a filename), "
                             "manage (manage a single volume), "
                             "unmanage (unmanage a single volume)")
    parser.add_argument("--no-dry-run", dest='dry_run', action='store_false',
                        help="Run in non dry run mode", required=False)
    parser.add_argument("--dry-run", dest='dry_run', action='store_true',
                        help="Run in dry run mode (Default)", required=False)
    parser.set_defaults(dry_run=Config.DEFAULT_IS_DRY_RUN)
    parser.add_argument("--vm", help="VM uuid/name", required=False)
    parser.add_argument("--vpc", help="VPC uuid", required=False)
    parser.add_argument("--filename", help="filename with names/uuid of VMs to migrate", required=False)
    parser.add_argument("--skip-sg", action='store_true', help="skip security-groups", default=False, required=False)
    parser.add_argument("--ignore-vm-state", action='store_true',
                        help="Ignore source VM state when transferring VM definition", default=False, required=False)
    parser.add_argument("--ipdb", action='store_true', help="give me ipdb with clients and continue",
                        default=False, required=False)
    parser.add_argument("--also-mirror-volumes", dest='use_only_mirror_jobs', action='store_false',
                        help="By default only look for mirror jobs"
                             "this flag allow to use volumes from broken mirror jobs",
                        default=True, required=False)
    parser.add_argument("--volume-id", help="Just manage volume", default=False, required=False)
    parser.add_argument("--volume-name", help="Name for managed volume", default=None, required=False)
    parser.add_argument("--use-cc-passthrough", action='store_true', default=False,
                        help="Access VPSA using CC pass through mode (when VPSA is not directly accessible")
    # Specify output of "--version"
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s (version {version})".format(version=__version__))
    return parser.parse_args()


if __name__ == "__main__":
    """ This is executed when run from the command line """
    args = parse_arguments()
    init_logger(vm_id=args.vm)
    arguments = args

    if args.ipdb:
        get_to_ipdb()

    if args.op == 'migrate':
        if not args.vm:
            logger.info("Please provide the VM name/UUID you want to migrate")
            sys.exit(1)
        migrate_vm(args.vm, args.vpc)
        sys.exit(0)
    if args.op == 'migrate_vpc_vms':
        if not args.vpc:
            logger.info("Please provide the VPC ID fir the you want to migrate")
            sys.exit(1)
        migrate_vpc_vms(args.vpc)
        sys.exit(0)
    elif args.op == 'manage':
        if args.volume_id:
            manage_single_volume(args.volume_id, args.volume_name)
            sys.exit(0)
        else:
            logger.info("Please provide the volume UUID you want to manage")
            sys.exit(1)
    elif args.op == 'unmanage':
        if args.volume_id:
            unmanage_single_volume(args.volume_id)
            sys.exit(0)
        else:
            logger.info("Please provide the volume UUID you want to unmanage")
            sys.exit(1)
    elif args.op == 'migrate_all':
        vms_to_migrate = []
        if args.filename:
            with open(args.filename) as f:
                all_vm_names = f.read()
                vms_to_migrate = all_vm_names.split()
        logger.info("Migrating a list of VMs: %s", vms_to_migrate)
        for vm_name in vms_to_migrate:
            answer = raw_input("Migrate {} [Y/n]? ".format(vm_name))
            if answer == 'Y':
                try:
                    migrate_vm(vm_name)
                except Exception as ex:
                    logger.exception("Failed migrating VM: %s", vm_name)
            else:
                logger.info("Skipping %s", vm_name)
    else:
        logger.info("Please provide a valid op, one of:  migrate/migrate_all/manage/unmanage")
        sys.exit(1)
