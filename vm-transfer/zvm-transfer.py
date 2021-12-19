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
from pprint import pformat, pprint
from munch import unmunchify

import symphony_client
from config import Config

LOGS_DIR = "."
ZVM_CLONE_LOGS_DIR = LOGS_DIR + "/zvm-transfer-logs"
LOGGER_NAME = "zvm-transfer"
VPSA_VOLUME_TEMPLATE = 'neokarm_volume-{}'

DRY_RUN = Config.DRY_RUN

logger = logging.getLogger(LOGGER_NAME)

arguments = None


def migrate_vm(vm_id_or_name):
    logger.info("vm_id: %s", vm_id_or_name)

    src_symp_client = init_src_symp_client()
    vm_list = src_symp_client.vms.list(detailed=True)
    vm = get_vm_by_id(src_symp_client, vm_id_or_name, vm_list)
    if not vm:
        vm = get_vm_by_name(src_symp_client, vm_id_or_name)
        if not vm:
            sys.exit(1)
    vm_id = vm.id
    if vm.status == 'active':
        logger.info("VM {} ({}) is active in source cluster".format(vm.name, vm_id))
        sys.exit(1)

    dst_symp_client = init_dst_symp_client()
    dest_vm = get_vm_by_name(dst_symp_client, vm.name)
    if dest_vm:
        logger.info("VM {} ({}) already exists in destination".format(dest_vm.name, dest_vm.id))
        sys.exit(1)

    networks = create_networking_map(src_symp_client, dst_symp_client, vm)
    manageable_volumes, existing_volumes = check_volumes_in_dest(vm, dst_symp_client)

    create_new_vm(vm, networks, manageable_volumes, existing_volumes, dst_symp_client)

    logger.info("VM %s cloning is complete", vm.name)


def get_vm_by_id(client, vm_id, vm_list=None):
    if vm_list is None:
        vm_list = client.vms.list(detailed=True)
    filtered_vm_list = [vm for vm in vm_list if vm.id == vm_id]
    if not filtered_vm_list:
        logger.info("VM with id: %s does not exist", vm_id)
        return None
    return filtered_vm_list[0]


def get_vm_by_name(client, vm_name, vm_list=None):
    if vm_list is None:
        vm_list = client.vms.list(detailed=True)
    filtered_vm_list = [vm for vm in vm_list if vm.name == vm_name]
    if not filtered_vm_list:
        logger.info("VM with name: %s does not exists", vm_name)
        return None
    return filtered_vm_list[0]


def init_src_symp_client():
    my_session = requests.Session()
    my_session.verify = False
    client = symphony_client.Client(url='https://%s' % Config.SRC_CLUSTER_IP, session=my_session)
    client.login(domain=Config.SRC_ACCOUNT,
                 username=Config.SRC_USERNAME,
                 password=Config.SRC_PASSWORD,
                 project='default',
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


def extract_vm_info(vm):
    logger.info("Extracting info from VM:\n%s", pformat(unmunchify(vm)))
    vm_info = dict()
    vm_info['name'] = vm['name']
    vm_info['disable_delete'] = vm['disable_delete']
    vm_info['hw_firmware_type'] = vm['hw_firmware_type']
    vm_info['instanceType'] = vm['instanceType']
    vm_info['instance_profile'] = vm['instance_profile']
    vm_info['key_pair'] = vm['key_pair']
    vm_info['metadata'] = vm['metadata']
    vm_info['provided_os_type_id'] = vm['provided_os_type_id']
    vm_info['ramMB'] = vm['ramMB']
    vm_info['restart_on_failure'] = vm['restart_on_failure']
    vm_info['vcpus'] = vm['vcpus']
    vm_info['ports'] = vm['ports']
    vm_info['tags'] = [tag for tag in vm['tags'] if not tag.startswith('system:')]


    #vm_info['project_id'] = get_dst_project_id(vm['project_id'], src_client, dst_client)
    #vm_info['bootVolume'] = get_dst_boot_volume_id(vm['bootVolume'], src_client, dst_client)
    #vm_info['volumes'] = get_dst_volumes_ids(vm['volumes'], src_client, dst_client)
    #vm_info['imageId'] = get_dst_image_id(vm['imageId'], src_client, dst_client)
    #vm_info['networks'] = get_dst_networks(vm['networks'], src_client, dst_client)
    logger.info("vm_info: %s", vm_info)
    return vm_info


def create_networking_map(src_client, dst_client, vm):
    src_networks = src_client.vpcs.networks.list(project_id=Config.SRC_PROJECT)
    src_networks_id_to_name = {network.id: network.name for network in src_networks}
    if len(src_networks) != len(src_networks_id_to_name):
        msg = "There are at least two networks with the same name in the source"
        logger.info(msg)
        raise Exception(msg)
    dst_networks = dst_client.vpcs.networks.list(project_id=Config.DST_PROJECT)
    dst_networks_name_to_id = {network.name: network.id for network in dst_networks}
    if len(dst_networks) != len(dst_networks_name_to_id):
        msg = "There are at least two networks with the same name in the destinations"
        logger.info(msg)
        raise Exception(msg)

    all_security_group_names = set()
    networks = list()
    for port in vm.ports:
        source_network_name = src_networks_id_to_name.get(port.network_id)
        if source_network_name is None:
            msg = "Didn't find network %s name in source" % port.network_id
            logger.info(msg)
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
        existing_sg = dst_client.vpcs.security_groups.list(project_id=Config.DST_PROJECT, name=list(security_group_names))
        if len(existing_sg) != len(all_security_group_names):
            msg = "Didn't find matching security_groups in destination out of: %s" % all_security_group_names
            logger.info(msg)
            if arguments.skip_sg:
                network.pop('security_groups')
            else:
                raise Exception(msg)
        networks.append(network)
    return networks


def manage_single_volume(volume_id, volume_name):
    dst_client = init_dst_symp_client()
    manageable_volumes = dst_client.meletvolumes.list_manageable(Config.DST_POOL_ID)
    existing_volumes = [volume for volume in dst_client.meletvolumes.list() if volume.storagePool == Config.DST_POOL_ID]
    manage_volume(dst_client, manageable_volumes, existing_volumes, volume_id, 0, None, volume_name=volume_name)


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


def manage_volumes_in_dest(vm, dst_client, manageable_volumes, existing_volumes):
    # Manage
    index = 0
    manage_volume(dst_client, manageable_volumes, existing_volumes, vm.bootVolume, index, vm)
    for volume in vm.volumes:
        index = index + 1
        manage_volume(dst_client, manageable_volumes, existing_volumes, volume, index, vm)


def check_volumes_in_dest(vm, dst_client):
    manageable_volumes = dst_client.meletvolumes.list_manageable(Config.DST_POOL_ID)
    existing_volumes = [volume for volume in dst_client.meletvolumes.list() if volume.storagePool == Config.DST_POOL_ID]
    # Manage
    index = 0
    check_manage_volume(manageable_volumes, existing_volumes, vm.bootVolume)
    for volume in vm.volumes:
        index = index + 1
        check_manage_volume(manageable_volumes, existing_volumes, volume)
    return manageable_volumes, existing_volumes


def manage_volume(dst_client, manageable_volumes, existing_volumes, volume_id, index, vm, ignore_exists=True, volume_name=None):
    check_manage_volume(manageable_volumes, existing_volumes, volume_id, ignore_exists=ignore_exists)
    # Manage volume if not exists
    existing_vol = [v for v in existing_volumes if v.id == volume_id]
    if not existing_vol:
        if index > 0:
            name = "volume #{} for {}".format(index, vm.id) if vm else volume_name or "Volume {}".format(volume_id)
        elif index == 0:
            name = "bootVolume #{} for {}".format(index, vm.id) if vm else volume_name or "Volume {}".format(volume_id)
        else:
            raise Exception("Invalid volume index %s" % index)
        dst_client.meletvolumes.manage(name=name,
                                       storage_pool=Config.DST_POOL_ID,
                                       reference={"name": VPSA_VOLUME_TEMPLATE.format(volume_id)},
                                       project_id=Config.DST_PROJECT,
                                       volume_id=volume_id)


def check_manage_volume(manageable_volumes, existing_volumes, volume_id, ignore_exists=True):
    volume_to_manage = [volume for volume in manageable_volumes if
                        volume.reference.name == VPSA_VOLUME_TEMPLATE.format(volume_id)]
    if ignore_exists:
        existing_vol = [v for v in existing_volumes if v.id == volume_id]
        if existing_vol:
            logger.info("Requested volume already exists - skipping")
            return
    if volume_to_manage:
        logger.info("Found volume to manage = %s", volume_to_manage)
        volume_to_manage = volume_to_manage[0]
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
            return


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


def create_new_vm(vm, networks, manageable_volumes, existing_volumes, dst_client):
    filtered_tags = [tag for tag in vm.tags if not tag.startswith('system:')] or None
    guest_os = None
    if 'system:os_family_windows' in vm.tags:
        guest_os = 'windows'
    if vm.get('managing_resource', {}).get('resource_id'):
        logger.info("VM %s is a managed VM - skipping", pformat(vm.name))
        return

    vm_params = dict(instance_type=vm.instanceType,
                     project_id=Config.DST_PROJECT,
                     restart_on_failure=False,
                     tags=filtered_tags,
                     boot_volumes=[vm.bootVolume],
                     volumes_to_attach=vm.volumes,
                     hw_firmware_type=vm.hw_firmware_type,
                     networks=networks,
                     guest_os=guest_os,
                     os_type_id=vm.provided_os_type_id,
                     powerup=False)
    logger.info("VM Creation params:\n%s", pformat(vm_params))
    if Config.DRY_RUN:
        logger.info("Dry run - not creating")
        return
    manage_volumes_in_dest(vm, dst_client, manageable_volumes, existing_volumes)

    created_vm = dst_client.vms.create(name=vm.name,
                                       instance_type=vm.instanceType,
                                       project_id=Config.DST_PROJECT,
                                       restart_on_failure=False,
                                       tags=filtered_tags,
                                       boot_volumes=[{"id": vm.bootVolume, "disk_bus": "virtio", "device_type": "disk"}],
                                       volumes_to_attach=vm.volumes,
                                       hw_firmware_type=vm.hw_firmware_type,
                                       networks=networks,
                                       guest_os=guest_os,
                                       os_type_id=vm.provided_os_type_id,
                                       powerup=False)
    logger.info("Created VM:\n%s", pformat(created_vm))


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


def get_to_ipdb():
    import ipdb; ipdb.set_trace()
    src_client = init_src_symp_client()
    dst_client = init_dst_symp_client()


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("op", choices=['migrate', 'migrate_all', 'manage', 'unmanage'],
                        help="Operation to perform. one of: "
                             "migrate (migrate a VM), "
                             "migrate_all (migrate a list of VMs - from the script), "
                             "manage (manage a single volume), "
                             "unmanage (unmanage a single volume)")
    parser.add_argument("--vm", help="VM uuid/name", required=False)
    parser.add_argument("--skip-sg", action='store_true', help="skip security-groups", default=False, required=False)
    parser.add_argument("--ipdb", action='store_true', help="give me ipdb with clients and continue", default=False, required=False)
    parser.add_argument("--volume-id", help="Just manage volume", default=False, required=False)
    parser.add_argument("--volume-name", help="Name for managed volume", default=None, required=False)

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
        migrate_vm(args.vm)
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
    elif args.op != 'migrate_all':
        logger.info("Please provide a valid op, one of:  migrate/migrate_all/manage/unmanage")
        sys.exit(1)

    vms_to_migrate = [
        # "psg-prisql",
        # "megama-app-p1",
        # "psg-dc1",
        # "psg-dc3",
        # "psg-sql01",
        # "pri-app-p1",
        # "rds-host-p1",
        # "danel-sql-t1",
        # "bse-sql-t1", # $$$$ two volumes
        # "danel-app-p1",
        # "my-be-web-t1",
        # "commug-web-p1",
        # "pro-mgmt-t1",
        # "psg-dev",
        # "rds-brk-p1",
        # "joshua-app-p1",
        # "site-web-t1",
        # "joshua-app-p3",
        # "gto-app-p1",
        # "pro-web-t1",
        # "psg-dc01",
        # "psg-mgmt01",
        # "bse-srv-d1",
        # "Template",
        # "my-web-t1",
        # "site-mgmt-t1",
        # "ovedgubi-sql-t1",
        # "terminal-app-p1",
        # "commug-sql-t1",
        # "rds-host-p5",
        # "joshua-app-t1",
        # "commug-web-t1",
        # "danel-app-t1",
        # "pro-sql-t1",
        # "psg-fs01",
        # "my-web-p1",
        # "psg-mcepo",
        # "pro-web-p1",
        # "rds-host-p3",
        # "pro-mgmt-p1",
        # "site-mgmt-p1",
        # "danel-sql-p1",
        # "W2K12R2DC",  -- In different VPC ignored
    ]
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
