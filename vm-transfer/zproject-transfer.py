#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
A python script that clones a Project from the source system to the destination system
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
import time
import copy

from monotonic import monotonic
from pprint import pformat, pprint
from munch import Munch, unmunchify
from config import Config

import symphony_client

LOGS_DIR = "."
ZVM_CLONE_LOGS_DIR = LOGS_DIR + "/zvm-transfer-logs"
LOGGER_NAME = "zproject-transfer"
SRC_NONAME_TEMPLATE = "src_{}"
SRC_MAIN_RTB_NONAME_TEMPLATE = "main_src_{}"
logger = logging.getLogger(LOGGER_NAME)

arguments = None


def init_logger(name):
    formatter = logging.Formatter('%(asctime)s [%(name)s] %(levelname)-10s %(message)s')
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if not os.path.exists(ZVM_CLONE_LOGS_DIR):
        os.makedirs(ZVM_CLONE_LOGS_DIR)

    logfile = '{logger_name}-{name}.log'.format(logger_name=LOGGER_NAME, name=name)
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


def init_dst_symp_client():
    return BaseMigrator.init_client(Config.DST_CLUSTER_IP,
                                    Config.DST_ACCOUNT,
                                    Config.DST_USERNAME,
                                    Config.DST_PASSWORD,
                                    Config.DST_PROJECT_ID,
                                    Config.DST_MFA_SECRET)


def get_to_ipdb():
    # dst_client = init_dst_symp_client()
    # vpsa_requester = get_vpsa_requester(dst_client, Config.DST_POOL_ID)
    import ipdb; ipdb.set_trace()


def filter_nones(**dict_to_filter):
    return {key: value for key, value in dict_to_filter.iteritems() if value is not None}


class BaseMigrator(object):
    def __init__(self, args, transfer_src_project, transfer_dst_project=None):
        self.args = args
        self.cluster_dump = self._load_cluster_dump()
        self.transfer_src_project_id = None
        self.transfer_src_project = self._get_id_for_name_or_id("projects", transfer_src_project)
        all_projects_names = self._get_field_for_all_object_of_type("projects", "name")
        if not self.transfer_src_project:
            self._log_and_raise("Could not find project {} in source cluster dump. Available: {}".format(
                transfer_src_project, all_projects_names))
        else:
            self.transfer_src_project_id = self.transfer_src_project["id"]
        self.client = self.init_client(Config.DST_CLUSTER_IP,
                                       Config.DST_ACCOUNT,
                                       Config.DST_USERNAME,
                                       Config.DST_PASSWORD,
                                       Config.DST_PROJECT_ID,
                                       Config.DST_MFA_SECRET)
        if transfer_dst_project:
            dst_projects_list = self.client.projects.list()
            self.transfer_dst_project = self._filter_array_of_dicts_by_attr(dst_projects_list,
                                                                            "name",
                                                                            transfer_dst_project)
            if not self.transfer_dst_project:
                self.transfer_dst_project = self._filter_array_of_dicts_by_attr(dst_projects_list,
                                                                                "id",
                                                                                transfer_dst_project)
            if not self.transfer_dst_project:
                self._log_and_raise("Could not find project {} in dest cluster".format(transfer_dst_project))
            self.transfer_dst_project = self.transfer_dst_project[0]
            self.transfer_dst_project_id = self.transfer_dst_project["id"]

    def _load_cluster_dump(self):
        if self.args.cluster_dump_file is None:
            logger.info("Please provide the cluster dump file")
            sys.exit(1)
        with open(self.args.cluster_dump_file) as f:
            cluster_dump = json.load(f)
        return cluster_dump

    @staticmethod
    def init_client(dst_cluster_ip, domain, username, password, project_id, mfa_secret):
        my_session = requests.Session()
        my_session.verify = False
        client = symphony_client.Client(url='https://%s' % dst_cluster_ip, session=my_session)
        client.login(domain=domain,
                     username=username,
                     password=password,
                     project=project_id,
                     mfa_secret=mfa_secret)
        return client

    @staticmethod
    def _filter_array_of_dicts_by_attr(aod, attr, value):
        filtered_dicts = [d for d in aod if d.get(attr) == value]
        return filtered_dicts

    def _get_field_for_all_object_of_type(self, object_type, field_name):
        objects = self.cluster_dump.get(object_type)
        return [o.get(field_name) for o in objects]

    def _get_id_for_name_or_id(self, object_type, name_or_id, id_is_unique=True, name_must_be_unique=True):
        objects = self.cluster_dump.get(object_type)
        if self.transfer_src_project_id:
            objects = self._filter_array_of_dicts_by_attr(objects, "project_id",
                                                          self.transfer_src_project_id)

        objects_by_name = self._filter_array_of_dicts_by_attr(
            objects,
            VpcMigrator.MONIKERS_MAP.get(object_type, {}).get("name", "name"),
            name_or_id)

        if name_must_be_unique and len(objects_by_name) > 1:
            logger.info("There are multiple %s with name %s: %s", object_type, name_or_id, objects_by_name)
            return None
        if len(objects_by_name) > 0:
            return objects_by_name[0]

        objects_by_id = self._filter_array_of_dicts_by_attr(
            objects,
            VpcMigrator.MONIKERS_MAP.get(object_type, {}).get("id", "id"),
            name_or_id)

        if id_is_unique and len(objects_by_name) > 1:
            logger.info("There are multiple %s with id %s: %s", object_type, name_or_id, objects_by_name)
            return None
        if len(objects_by_id) > 0:
            return objects_by_id[0]
        logger.info("No object %s with name or ID %s", object_type, name_or_id)
        return None

    @staticmethod
    def _log_and_raise(msg):
        logger.error(msg)
        raise Exception(msg)


class ProjectMigrator(BaseMigrator):
    def __init__(self, args, transfer_src_project, transfer_dst_project=None):
        super(ProjectMigrator, self).__init__(args, transfer_src_project, transfer_dst_project)

    def migrate_project(self):
        vpcs_to_migrate = self._filter_array_of_dicts_by_attr(self.cluster_dump['vpcs'],
                                                              "project_id",
                                                              self.transfer_src_project_id)
        for vpc in vpcs_to_migrate:
            vpc_migrator = VpcMigrator(self.args,
                                       transfer_src_project=self.transfer_src_project_id,
                                       transfer_dst_project = self.transfer_dst_project_id)
            vpc_migrator.migrate_vpc(vpc['id'])


class VpcMigrator(BaseMigrator):
    MONIKERS_MAP = {}
    VPC_CREATION_TIMEOUT = 120
    SUBNET_CREATION_TIMEOUT = 120

    def __init__(self, args, transfer_src_project, transfer_dst_project=None):
        super(VpcMigrator, self).__init__(args, transfer_src_project, transfer_dst_project)

    def _wait_for_all_vpc_subnets_ready(self, vpc_id):
        expiration = monotonic() + VpcMigrator.SUBNET_CREATION_TIMEOUT
        subnets = self.client.vpcs.networks.list(vpc_id=vpc_id)
        while monotonic() < expiration:
            if all([sn['state'] == 'available' for sn in subnets]):
                return subnets
            time.sleep(10)
            subnets = self.client.vpcs.networks.list(vpc_id=vpc_id)
        msg = "not all subnet for VPC {} are in available state: {}".format(
            vpc_id, [sn['id'] for sn in subnets if sn['state'] != 'available'])
        logger.error(msg)
        raise Exception(msg)

    def _wait_for_available_vpc(self, vpc_id):
        expiration = monotonic() + VpcMigrator.VPC_CREATION_TIMEOUT
        vpc = self.client.vpcs.get(vpc_id)
        while monotonic() < expiration:
            if vpc['state'] == 'available':
                return vpc
            time.sleep(10)
            vpc = self.client.vpcs.get(vpc_id)
        msg = "VPC {} not available status: {}".format(
            vpc_id, vpc['state'])
        logger.error(msg)
        raise Exception(msg)

    def _create_vpc(self, src_vpc_object):
        target_name = SRC_NONAME_TEMPLATE.format(src_vpc_object["name"])
        vpcs = self.client.vpcs.list(project_id=self.transfer_dst_project_id)
        # If this is default - don't care about the name
        if src_vpc_object['is_default']:
            filtered_vpcs = [vpc for vpc in vpcs if vpc['is_default']]
        else:
            filtered_vpcs = self._filter_array_of_dicts_by_attr(vpcs, "name", target_name)
        dst_vpc = None
        if len(filtered_vpcs) > 1:
            self._log_and_raise("There are already more than one VPCs with the same target name {}"
                                " for the source VPC {} in the destination".format(target_name, src_vpc_object["name"]))
        elif len(filtered_vpcs) == 0:
            create_params = filter_nones(cidr_block=src_vpc_object["cidr_block"],
                                         is_default=src_vpc_object['is_default'],
                                         name=target_name,
                                         description=src_vpc_object["description"],
                                         project_id=self.transfer_dst_project_id)
            logger.info("Creating VPC with the following parameters: %s", create_params)
            dst_vpc = self.client.vpcs.create(**create_params)
        else:
            dst_vpc = filtered_vpcs[0]
            if dst_vpc["cidr_block"] != src_vpc_object["cidr_block"]:
                self._log_and_raise("CIDR block of source VPC {} is different than existing dest VPC {}".format(
                    src_vpc_object["cidr_block"], dst_vpc["cidr_block"]))
            update_params = filter_nones(vpc_id=dst_vpc["id"],
                                         name=target_name,
                                         description=src_vpc_object["description"])
            logger.info("Updating VPC to the following parameters: %s", update_params)
            self.client.vpcs.update(**update_params)
        dst_vpc = self._wait_for_available_vpc(dst_vpc['id'])
        logger.info("VPC %s (%s) is available", dst_vpc['name'], dst_vpc['id'])
        return dst_vpc

    def _align_src_vpc_to_dst(self, src_vpc_object, dst_vpc):
        self._align_src_obj_tags_to_dst(self.client.vpcs, "vpc_ids", src_vpc_object, dst_vpc)
        if src_vpc_object['enable_dns_support'] != dst_vpc['enable_dns_support']:
            self.client.vpcs.update(vpc_id=dst_vpc['id'],
                                    enable_dns_support=src_vpc_object['enable_dns_support'],
                                    enable_dns_hostnames=src_vpc_object['enable_dns_hostnames'])
        dst_vpc = self.client.vpcs.get(vpc_id=dst_vpc['id'])
        return dst_vpc

    @staticmethod
    def _align_src_obj_tags_to_dst(client_prefix, id_moniker, src_obj, dst_obj):
        src_tags_set = set(src_obj['tags'] or [])
        dst_tags_set = set(dst_obj['tags'] or [])
        tags_to_add = src_tags_set - dst_tags_set
        tags_to_remove = dst_tags_set - src_tags_set
        if tags_to_add:
            params = {
                id_moniker: [dst_obj['id']],
                "tags": list(tags_to_add)
            }
            client_prefix.add_tags(**params)
        if tags_to_remove:
            params = {
                id_moniker: [dst_obj['id']],
                "tags": list(tags_to_remove)
            }
            client_prefix.remove_tags(**params)

    def _create_dhcp_options(self, src_vpc_object, dst_vpc):
        src_dhcp_options = self._filter_array_of_dicts_by_attr(self.cluster_dump.get("dhcp_options"),
                                                               "id",
                                                               src_vpc_object["dhcp_options_id"])
        if not src_dhcp_options:
            self._log_and_raise("Did not find the source DHCP options: {}".format(src_vpc_object["dhcp_options_id"]))
        src_dhcp_options = src_dhcp_options[0]
        # check for default dhcp options:
        if src_dhcp_options['is_default']:
            logger.info("VPC %s Will use the default DHCP options", dst_vpc['id'])
            return None
        # check for existing dhcp options by name (if it's not empty/None)
        dst_dhcp_options = None
        if src_dhcp_options["name"]:
            existing = self.client.vpcs.dhcp_options.list(project_id=self.transfer_dst_project_id,
                                                          name=src_dhcp_options['name'])
            if existing and len(existing) == 1:
                logger.info("Using existing DHCP option by name: {name} ({id})".format(name=src_dhcp_options['name'],
                                                                                       id=src_dhcp_options['id']))
                dst_dhcp_options = existing[0]
            elif len(existing) > 1:
                logger.info("Multiple DHCP option with name: {name}: {ids}".format(name=src_dhcp_options['name'],
                                                                                   ids=[do.id for do in existing]))
        if dst_dhcp_options is None:
            create_params = filter_nones(name=src_dhcp_options["name"],
                                         description=src_dhcp_options["description"],
                                         dhcp_options=src_dhcp_options["options"],
                                         project_id=dst_vpc['project_id'])
            logger.info("Creating DHCP Options with params: %s", create_params)
            dst_dhcp_options = self.client.vpcs.dhcp_options.create(**create_params)
        logger.info("Created DHCP Options %s", dst_dhcp_options)
        logger.info("Associating VPC %s with DHCP Options %s", dst_vpc['id'], dst_dhcp_options['id'])
        self.client.vpcs.associate_dhcp_options(dst_vpc['id'], dst_dhcp_options['id'])
        self._align_src_obj_tags_to_dst(self.client.vpcs.dhcp_options, "dhcp_options_id", src_dhcp_options, dst_dhcp_options)
        return dst_dhcp_options

    def _create_security_groups(self, src_vpc_object, dst_vpc):
        src_security_groups = self._filter_array_of_dicts_by_attr(self.cluster_dump.get("security_groups"),
                                                                  "vpc_id",
                                                                  src_vpc_object["id"])
        src_security_groups_by_name = {sg['name']: sg for sg in src_security_groups}
        current_dst_security_groups = self.client.vpcs.security_groups.list(vpc_id=dst_vpc['id'])
        current_dst_security_groups_by_name = {sg['name']: sg for sg in current_dst_security_groups}
        for sg in src_security_groups:
            if sg['name'] not in current_dst_security_groups_by_name.keys():
                logger.info("Creating SG %s in VPC %s", sg['name'], dst_vpc['id'])
                self.client.vpcs.security_groups.create(name=sg['name'], vpc_id=dst_vpc['id'])
        current_dst_security_groups = self.client.vpcs.security_groups.list(vpc_id=dst_vpc['id'])
        current_dst_security_groups_by_name = {sg['name']: sg for sg in current_dst_security_groups}
        # Need to set all rules after SG exists - as there may be rules with remote groups
        # Also align tags
        for dst_sg in current_dst_security_groups:
            src_sg = src_security_groups_by_name.get(dst_sg['name'])
            if src_sg is None:
                logger.warning("Could not find %s SG in source VPC", dst_sg['name'])
                continue
            # Keep only SG names & description in rules
            ingress_rules = copy.deepcopy(src_sg['ip_permissions_ingress'])
            for ingress_rule in ingress_rules:
                for group in ingress_rule['groups']:
                    group["group_id"] = current_dst_security_groups_by_name[group["group_name"]]['id']
                    group.pop("vpc_id", None)
                    group.pop("user_id", None)
            egress_rules = copy.deepcopy(src_sg['ip_permissions_egress'])
            for egress_rule in egress_rules:
                for group in egress_rule['groups']:
                    group["group_id"] = current_dst_security_groups_by_name[group["group_name"]]['id']
                    group.pop("vpc_id", None)
                    group.pop("user_id", None)
            logger.info("Setting SG %s (%s) rules: ingress: %s, egress: %s",
                        dst_sg['name'], dst_sg['id'],
                        ingress_rules, egress_rules)
            self.client.vpcs.security_groups.set_rules(
                group_id=dst_sg['id'],
                permissions={"ip_permissions_ingress": ingress_rules,
                             "ip_permissions_egress": egress_rules})
            self._align_src_obj_tags_to_dst(self.client.vpcs.security_groups, "security_group_id", src_sg, dst_sg)
        current_dst_security_groups = self.client.vpcs.security_groups.list(vpc_id=dst_vpc['id'])
        return current_dst_security_groups

    def _create_internet_gateway(self, src_vpc_object, dst_vpc):
        # attachment-vpc-id
        internet_gateways = self._filter_array_of_dicts_by_attr(self.cluster_dump.get("internet_gateways"),
                                                                "project_id",
                                                                src_vpc_object["project_id"])
        src_internet_gateway = [ig.get('attachment_set')[0]['vpc_id'] for ig in internet_gateways
                                if ig.get('attachment_set', [{}])[0].get('vpc_id') == dst_vpc['id']]
        if src_internet_gateway:
            src_internet_gateway = src_internet_gateway[0]
        else:
            return None

        dst_internet_gateway = self.client.vpcs.internet_gateways.list(attachment_vpc_id=dst_vpc['id'])
        if dst_internet_gateway:
            dst_internet_gateway = dst_internet_gateway[0]
            update_params = filter_nones(id=dst_internet_gateway['id'],
                                         name=src_internet_gateway['name'],
                                         description=src_internet_gateway['description'])
            dst_internet_gateway = self.client.vpcs.internet_gateways.update(**update_params)
            return dst_internet_gateway
        create_params = filter_nones(name=src_internet_gateway['name'],
                                     description=src_internet_gateway['description'],
                                     project_id=src_vpc_object["project_id"])
        dst_internet_gateway = self.client.vpcs.internet_gateways.create(**create_params)
        self.client.vpcs.internet_gateways.attach(internet_gateway=dst_internet_gateway['id'],
                                                  vpc_id=dst_vpc['id'])
        dst_internet_gateway = self.client.vpcs.internet_gateways.get(dst_internet_gateway['id'])
        self._align_src_obj_tags_to_dst(self.client.vpcs.internet_gateways, "internet_gateway_id",
                                        src_internet_gateway, dst_internet_gateway)
        return dst_internet_gateway

    @staticmethod
    def _is_main_route_table(route_table):
        for assoc_sec in route_table.get('association_set', []):
            if assoc_sec['main'] is True:
                return True
        return False

    def _create_route_tables(self, src_vpc_object, dst_vpc):
        src_route_tables = self._filter_array_of_dicts_by_attr(self.cluster_dump.get("route_tables"),
                                                               "vpc_id",
                                                               src_vpc_object["id"])
        # need to handle main route-table (which usually doesn't have a name but is the default)
        src_route_tables_by_name = {rtb['name'] or SRC_NONAME_TEMPLATE.format(rtb['id']): rtb for rtb in src_route_tables
                                    if not self._is_main_route_table(rtb)}
        src_main_route_table = [rtb for rtb in src_route_tables if self._is_main_route_table(rtb)]
        if not src_main_route_table:
            self._log_and_raise("Main route table for source VPC {} was not found".format(src_vpc_object["id"]))
        src_main_route_table = src_main_route_table[0]
        current_route_tables = self.client.vpcs.route_tables.list(vpc_id=dst_vpc['id'])
        current_route_tables_by_name = {rtb['name']: rtb for rtb in current_route_tables
                                        if not self._is_main_route_table(rtb)}
        current_main_route_table = [rtb for rtb in current_route_tables if self._is_main_route_table(rtb)]
        if not current_main_route_table:
            self._log_and_raise("Main route table for dest VPC {} was not found".format(dst_vpc["id"]))
        current_main_route_table = current_main_route_table[0]
        update_params = filter_nones(
            route_table_id=current_main_route_table["id"],
            name=src_main_route_table['name'] or SRC_MAIN_RTB_NONAME_TEMPLATE.format(src_main_route_table['id']),
            description=src_main_route_table['description'])
        self.client.vpcs.route_tables.update(**update_params)
        # if we only have one route_table - it is the default rtb and it is not part of this list
        if len(src_route_tables_by_name) == len(current_route_tables_by_name):
            logger.info("No need to create additional route_tables we have %s (except for main)",
                        len(current_route_tables_by_name))
        elif len(src_route_tables_by_name) > len(current_route_tables_by_name):
            remaining_rtb_to_create = set(src_route_tables_by_name.keys()) - set(current_route_tables_by_name.keys())
            logger.info("We need to create additional %s route_tables", len(remaining_rtb_to_create))
            for src_rtb_name in remaining_rtb_to_create:
                src_rtb = src_route_tables_by_name[src_rtb_name]
                create_params = filter_nones(name=src_rtb['name'] or SRC_NONAME_TEMPLATE.format(src_rtb['id']),
                                             description=src_rtb['description'],
                                             vpc_id=dst_vpc['id'])
                logger.info("We need to create additional %s route_tables", len(remaining_rtb_to_create))
                self.client.vpcs.route_tables.create(**create_params)
        current_route_tables = self.client.vpcs.route_tables.list(vpc_id=dst_vpc['id'])
        return current_route_tables

    def _create_direct_subnet(self, src_vpc_object, dst_vpc, dst_route_tables):
        src_direct_subnet = self._filter_array_of_dicts_by_attr(self.cluster_dump.get("direct_networks"),
                                                                "vpc_id",
                                                                src_vpc_object["id"])
        if not src_direct_subnet:
            logger.info("No direct subnet in this VPC")
            return None
        src_direct_subnet = src_direct_subnet[0]
        logger.info("Source direct subnet for this VPC:\n%s", pformat(src_direct_subnet))
        dst_direct_subnet = self.client.vpcs.direct_networks.list(project_id=dst_vpc['project_id'])
        if dst_direct_subnet:
            dst_direct_subnet = dst_direct_subnet[0]
            logger.info("The direct subnet in this Project already exists: %s", dst_direct_subnet["id"])
            if dst_direct_subnet.get('vpc_id') and dst_direct_subnet['vpc_id'] != dst_vpc["id"]:
                self._log_and_raise("The direct network {} in this project is already associated "
                                    "to a different VPC".format(dst_direct_subnet["id"], dst_direct_subnet['vpc_id']))
            elif dst_direct_subnet.get('vpc_id') is None:
                logger.info("Associating direct-network %s to VPC %s", dst_direct_subnet["id"], dst_vpc["id"])
                self.client.vpcs.direct_networks.attach(network_id=dst_direct_subnet["id"], vpc_id=dst_vpc["id"])
            self.client.vpcs.direct_networks.update(network_id=dst_direct_subnet["id"],
                                                    name=dst_direct_subnet["name"],
                                                    description=dst_vpc["description"])
        else:
            self._log_and_raise("No direct subnet for this Project/VPC\n"
                                "you need to create it in the project prior to migrating this VPC")
        return dst_direct_subnet

    def _create_subnets(self, src_vpc_object, dst_vpc):
        src_subnets = self._filter_array_of_dicts_by_attr(self.cluster_dump.get("subnets"),
                                                          "vpc_id",
                                                          src_vpc_object["id"])
        dst_subnets = self.client.vpcs.networks.list(vpc_id=dst_vpc['id'])
        dst_subnets_by_cidr = {subnet['cidr_block']: subnet for subnet in dst_subnets}
        for src_subnet in src_subnets:
            if not src_subnet['is_direct_network']:
                if src_subnet['cidr_block'] not in dst_subnets_by_cidr.keys():
                    create_params = filter_nones(cidr_block=src_subnet['cidr_block'],
                                                 vpc_id=dst_vpc['id'],
                                                 name=src_subnet['name'],
                                                 description=src_subnet['description'])
                    logger.info("Creating dest subnet with params: %s", create_params)
                    self.client.vpcs.networks.create(**create_params)
                else:
                    dst_subnet = dst_subnets_by_cidr[src_subnet['cidr_block']]
                    logger.info("Dest subnet with CIDR %s in VPC %s already exist",
                                dst_subnet["cidr_block"], dst_vpc["id"])
                    update_params = filter_nones(network_id=dst_subnet["id"],
                                                 name=src_subnet['name'],
                                                 description=src_subnet['description'])
                    logger.info("Updating dest subnet with params: %s", update_params)
                    self.client.vpcs.networks.update(**update_params)
        # Make sure default subnet is the correct subnet
        dst_subnets = self._wait_for_all_vpc_subnets_ready(dst_vpc['id'])
        dst_subnets_by_cidr = {subnet['cidr_block']: subnet for subnet in dst_subnets}
        for src_subnet in src_subnets:
            dst_subnet = dst_subnets_by_cidr[src_subnet['cidr_block']]
            if src_subnet['is_default'] and not dst_subnet['is_default']:
                logger.info("Setting dest subnet %s (%s) as default subnet", dst_subnet['name'], dst_subnet['id'])
                self.client.vpcs.networks.set_default(dst_subnet['id'])
            elif src_subnet['is_default'] and dst_subnet['is_default']:
                logger.info("Dest subnet %s (%s) already set as default subnet", dst_subnet['name'], dst_subnet['id'])
            self._align_src_obj_tags_to_dst(self.client.vpcs.networks, "networks_id", src_subnet, dst_subnet)
        return dst_subnets

    def _associate_subnets(self, src_vpc_object, dst_vpc, dst_route_tables, dst_subnets):
        src_route_tables = self._filter_array_of_dicts_by_attr(self.cluster_dump.get("route_tables"),
                                                               "vpc_id",
                                                               src_vpc_object["id"])
        src_route_tables_by_name = {rtb['name'] or SRC_NONAME_TEMPLATE.format(rtb['id']): rtb for rtb in src_route_tables
                                    if not self._is_main_route_table(rtb)}
        # if we are here main_route_table must exists
        main_route_table = [rtb for rtb in src_route_tables if self._is_main_route_table(rtb)][0]
        dst_main_route_table_name = main_route_table['name'] or \
            SRC_MAIN_RTB_NONAME_TEMPLATE.format(main_route_table['id'])
        src_route_tables_by_name[dst_main_route_table_name] = main_route_table
        src_subnets = self._filter_array_of_dicts_by_attr(self.cluster_dump.get("subnets"),
                                                          "vpc_id",
                                                          src_vpc_object["id"])
        src_subnets_by_id = {subnet['id']: subnet for subnet in src_subnets}
        dst_route_tables_by_name = {rtb['name']: rtb for rtb in dst_route_tables}
        dst_subnets_by_cidr = {subnet['cidr_block']: subnet for subnet in dst_subnets}
        dst_subnets_id_set = {subnet['id'] for subnet in dst_subnets}
        for src_rtb in src_route_tables:
            dst_association_sec_by_network_id = dict()
            src_association_set = src_rtb.get('association_set', [])
            src_rtb_name = src_rtb['name'] or SRC_NONAME_TEMPLATE.format(src_rtb['id'])
            # different naming convention for main Route Table
            if self._is_main_route_table(src_rtb):
                src_rtb_name = src_rtb['name'] or SRC_MAIN_RTB_NONAME_TEMPLATE.format(src_rtb['id'])
            dst_rtb = dst_route_tables_by_name[src_rtb_name]
            for assoc in dst_rtb.get('association_set', []):
                if not assoc['main']:
                    dst_association_sec_by_network_id[assoc['network_id']] = assoc
            for association in src_association_set:
                if not association['main']:
                    src_subnet = src_subnets_by_id.get(association['network_id'])
                    dst_subnet = dst_subnets_by_cidr[src_subnet['cidr_block']]
                    if dst_subnet['id'] not in dst_association_sec_by_network_id:
                        logger.info("Associating dst subnet {} ({}) to dst RTB {} ({})".format(
                            dst_subnet['id'], dst_subnet['name'], dst_rtb['id'], dst_rtb['name']))
                        self.client.vpcs.route_tables.associate(dst_rtb['id'], network_id=dst_subnet['id'])
                    else:
                        logger.info("Dest subnet {} ({}) already associated to dest RTB {} ({})".format(
                            dst_subnet['id'], dst_subnet['name'], dst_rtb['id'], dst_rtb['name']))
                    dst_subnets_id_set.remove(dst_subnet['id'])
        logger.info("The following Subnets are implicitly associated with the main route table: %s", dst_subnets_id_set)
        return None

    def migrate_vpc(self, vpc_name_or_id):
        src_vpc_object = self._get_id_for_name_or_id("vpcs", vpc_name_or_id)
        if not src_vpc_object:
            self._log_and_raise("Failed to find VPC with name/ID {}".format(vpc_name_or_id))
        if src_vpc_object['is_default'] and not self.args.import_default_vpc:
            self._log_and_raise("The source VPC is a default VPC")
        logger.info("Migrating VPC %s (%s)", src_vpc_object['name'], src_vpc_object['id'])
        dst_vpc = self._create_vpc(src_vpc_object)
        dst_vpc = self._align_src_vpc_to_dst(src_vpc_object, dst_vpc)
        dst_dhcp_options = self._create_dhcp_options(src_vpc_object, dst_vpc)
        dst_security_groups = self._create_security_groups(src_vpc_object, dst_vpc)
        dst_internet_gateway = self._create_internet_gateway(src_vpc_object, dst_vpc)
        dst_route_tables = self._create_route_tables(src_vpc_object, dst_vpc)
        direct_subnet = self._create_direct_subnet(src_vpc_object, dst_vpc, dst_route_tables)
        dst_subnets = self._create_subnets(src_vpc_object, dst_vpc)
        associate_subnets = self._associate_subnets(src_vpc_object, dst_vpc, dst_route_tables, dst_subnets)


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("op", choices=['migrate_project', 'migrate_vpc'],
                        help="Operation to perform. one of: "
                             "migrate_project (migrate a Project), "
                             "migrate_vpc (migrate a VPC in a project)")
    parser.add_argument("--no-dry-run", dest='dry_run', action='store_false',
                        help="Run in non dry run mode", required=False)
    parser.add_argument("--dry-run", dest='dry_run', action='store_true',
                        help="Run in dry run mode (Default)", required=False)
    parser.set_defaults(dry_run=Config.DEFAULT_IS_DRY_RUN)
    parser.add_argument("--transfer-src-project", help="Source project Name/ID to transfer from", required=False)
    parser.add_argument("--transfer-dst-project", help="Source project Name/ID to transfer to", required=False)
    parser.add_argument("--import-default-vpc", help="Import a default VPC to the project default VPC",
                        default=False, required=False, action='store_true')
    parser.add_argument("--vpc", help="Source VPC Name/ID", required=False)
    parser.add_argument("--cluster-dump-file", help="Filename of source cluster dump", required=False, default=None)
    parser.add_argument("--ipdb", action='store_true', help="give me ipdb with clients and continue",
                        default=False, required=False)
    # Specify output of "--version"
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s (version {version})".format(version=__version__))
    return parser.parse_args()


def main():
    """ This is executed when run from the command line """
    global arguments
    args = parse_arguments()
    init_logger("{}".format(args.vpc or args.transfer_src_project))
    arguments = args

    if args.ipdb:
        get_to_ipdb()

    if args.op == 'migrate_project':
        args.transfer_src_project = args.transfer_src_project or Config.SRC_TRANSFER_PROJECT_ID
        args.transfer_dst_project = args.transfer_dst_project or Config.DST_TRANSFER_PROJECT_ID
        if not args.transfer_src_project or not args.transfer_dst_project:
            logger.info("Please provide the source and destination Projects name/UUID for the migration")
            sys.exit(1)
        ProjectMigrator(args,
                        args.transfer_src_project,
                        args.transfer_dst_project).migrate_project()
        sys.exit(0)
    elif args.op == 'migrate_vpc':
        if not args.vpc:
            logger.info("Please provide the VPC name/UUID you want to migrate")
            sys.exit(1)
        args.transfer_src_project = args.transfer_src_project or Config.SRC_TRANSFER_PROJECT_ID
        args.transfer_dst_project = args.transfer_dst_project or Config.DST_TRANSFER_PROJECT_ID
        VpcMigrator(args,
                    args.transfer_src_project,
                    args.transfer_dst_project).migrate_vpc(args.vpc)
        sys.exit(0)
    else:
        logger.info("Please provide a valid op, one of:  migrate_project/migrate_vpc")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        if arguments and arguments.ipdb:
            import ipdb
            ipdb.set_trace()
        raise
