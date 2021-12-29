import argparse
import json
import logging
import time
import sys
from collections import namedtuple, OrderedDict
from os import path
import boto3
import munch

from inspector import runner
from inspector.tools import utils, inspectorlogger
from inspector.tools.inspectorlogger import logger
from strato_common import admin_creds
from strato_consts import apiconfig


class DatalayerTools(object):

    def __init__(self, client):
        self._runner_client = client
        self._clients = munch.Munch()

    def report_logical_inventory(self, **args):
        reporting_endpoint = None
        output_file = None
        local_file = args.get('local_file', None)
        if local_file:
            if local_file == '-':
                output_file = sys.stdout
            else:
                if path.exists(local_file):
                    raise Exception("Refusing to override {}".format(local_file))
                output_file = open(local_file, 'a')
        try:
            credentials = admin_creds.get_credentials(admin=True)
            data, failures = self.collect_logical_inventory(credentials)
            if output_file:
                json.dump(data, output_file)
                output_file.close()
                for object_name, failure in failures.iteritems():
                    logger.warning("Failed to collect inventory for %s: %s", object_name, failure)
                return
            if failures:
                logger.error("Error while trying to gather the logical inventory information, "
                             "only partial info is present")
        except Exception:
            logger.exception("Error while trying to gather the logical inventory information from the nodes")
            if not local_file:
                self._send_inventory_data_event(
                    event_definition=event_definitions.LOGICAL_INVENTORY_FAILED_TO_COLLECT,
                    entity_id=reporting_endpoint["id"] if reporting_endpoint else '',  # pylint: disable=unsubscriptable-object
                    entity_name=reporting_endpoint["name"] if reporting_endpoint else '')  # pylint: disable=unsubscriptable-object
            logger.error("An error occurred while running the tool \"report to hardware inventory\"")
            raise

    @staticmethod
    def _get_inventory_path_for_node(cloud_name, node_name):
        """
        Get the inventory S3 path for a specific node
        # < cloud_name > / <date> / < hostname >.json
        @param cloud_name: name of the cloud
        @param node_name: hostname of the node
        @return:  path to upload the node data into the s3 inventory
        """
        return HARDWARE_INVENTORY_PATH_TEMPLATE % dict(cloud_name=cloud_name,
                                                       node_name=node_name,
                                                       date=time.strftime('%Y-%m-%d'),
                                                       hour=time.strftime('%H'))

    @staticmethod
    def _get_logical_inventory_path(cloud_name):
        """
        Get the inventory S3 path for a specific node
        # < cloud_name > / <date> / < hour >_logical.json
        @param cloud_name: name of the cloud
        @param node_name: hostname of the node
        @return:  path to upload the node data into the s3 inventory
        """
        return LOGICAL_INVENTORY_PATH_TEMPLATE % dict(cloud_name=cloud_name,
                                                      date=time.strftime('%Y-%m-%d'),
                                                      hour=time.strftime('%H'))

    def _get_inventory_data_from_all_nodes(self, reporting_endpoint):
        """
        Gather the inventory data from all the nodes in the cluster
        @param reporting_endpoint: reporting endpoint for on-failure event details
        @return: data gathered from all the nodes
        """
        gather_data_cmd = "/usr/sbin/sn_inventory"
        try:
            return self._runner_client.run_on_all_nodes(gather_data_cmd, raise_on_failure=True)
        except Exception:  # pylint: disable=broad-except
            logger.error("Error while trying to gather the hardware inventory information from the nodes")
            DatalayerTools._send_inventory_data_event(event_definition=event_definitions.HW_INVENTORY_FAILED_TO_COLLECT,
                                                      entity_id=reporting_endpoint["id"],
                                                      entity_name=reporting_endpoint["name"])
            raise

    def _load_calls(self):  # pylint: disable=too-many-statements
        calls = OrderedDict()
        # engines
        calls['engines'] = self._clients.engine_manager_api.engines.list
        calls['engine_revisions'] = self._clients.engine_manager_api.engines.revisions.list
        calls['engine_versions'] = self._clients.engine_manager_api.engines.versions.list
        calls['engine_profiles'] = self._clients.engine_manager_api.engines.profiles.list
        # enternal endpoints
        calls['external_endpoints'] = self._clients.external_endpoint_api.externalendpoints.list
        calls['upgrades'] = self._clients.hot_upgrade_api.hot_upgrade.upgrades.list
        calls['upgrade_groups'] = self._clients.hot_upgrade_api.hot_upgrade.group_upgrade_tasks.list
        calls['upgrade_tasks'] = self._clients.hot_upgrade_api.hot_upgrade.upgrade_tasks.list
        # storage pool list
        calls['pools'] = self._clients.melet_api.storage.pools.list
        # Networking
        calls['ethernet_ifs'] = self._clients.stratonet_api.networking.ethernet_ifs.list
        calls['bond_ifs'] = self._clients.stratonet_api.networking.bond_ifs.list
        calls['link_ifs'] = self._clients.stratonet_api.networking.link_ifs.list
        calls['beacons_discovery'] = self._clients.stratonet_api.networking.discovery.list
        calls['vlan_ifs'] = self._clients.stratonet_api.networking.vlan_ifs.list
        calls['ipv4_ifs'] = self._clients.stratonet_api.networking.ipv4_ifs.list
        calls['virtual_ips'] = self._clients.stratonet_api.networking.virtual_ips.list
        calls['routes'] = self._clients.stratonet_api.networking.routes.list
        calls['traffic_ifs'] = self._clients.stratonet_api.networking.traffic_ifs.list
        calls['vn_group_ifs'] = self._clients.stratonet_api.networking.vn_group_ifs.list
        calls['vn_type'] = self._clients.stratonet_api.networking.vn_type.get_default_vn_type
        calls['proxy_settings_ifs'] = self._clients.stratonet_api.networking.proxy_settings_ifs.list
        # Images
        calls['machine_images'] = self._clients.image_manager_api.machine_images.list
        # VMS
        calls['cluster'] = self._clients.noded_api.cluster.summary
        calls['nodes'] = self._clients.noded_api.nodes.list
        calls['vms'] = (self._clients.vm_manager_api.vms.list, dict(detailed=True))
        calls['vm_snapshots'] = self._clients.vm_manager_api.vm_snapshots.list
        calls['vm_remote_snapshots'] = self._clients.vm_manager_api.remote_vm_snapshots.list
        calls['instance_types'] = self._clients.vm_manager_api.instance_types.list
        # Volumes
        calls['volumes'] = self._clients.volume_manager_api.volumes.list
        # VPCs
        calls['edge_networks'] = self._clients.vpc_manager_api.vpcs.admin.edge_network.list
        calls['edge_network_ip_pools'] = self._clients.vpc_manager_api.vpcs.admin.edge_network_ip_pool.list
        calls['direct_networks'] = self._clients.vpc_manager_api.vpcs.direct_networks.list
        calls['elastic_ips'] = self._clients.vpc_manager_api.vpcs.elastic_ips.list
        calls['vpcs'] = self._clients.vpc_manager_api.vpcs.list
        calls['internet_gateways'] = self._clients.vpc_manager_api.vpcs.internet_gateways.list
        calls['subnets'] = self._clients.vpc_manager_api.vpcs.networks.list
        calls['security_groups'] = self._clients.vpc_manager_api.vpcs.security_groups.list
        calls['dhcp_options'] = self._clients.vpc_manager_api.vpcs.dhcp_options.list
        calls['route_tables'] = self._clients.vpc_manager_api.vpcs.route_tables.list
        calls['network_interfaces'] = self._clients.vpc_manager_api.vpcs.network_interfaces.list
        calls['nat_gateways'] = self._clients.vpc_manager_api.vpcs.nat_gateways.list
        calls['peering'] = self._clients.vpc_manager_api.vpcs.peering.list
        calls['vpc_dns'] = self._clients.vpc_manager_api.vpcs.dns.list
        calls['nameservers'] = self._clients.route53_api.route53.nameservers.list
        calls['zones'] = (self._clients.route53_api.route53.zones.list, dict(with_associated_vpcs=True))
        calls['system_zones'] = (self._clients.route53_api.route53.zones.list, dict(with_associated_vpcs=True, system=True))
        calls['accounts'] = self._clients.identity_manager_api.identity.domains.list
        calls['projects'] = self._clients.identity_manager_api.identity.projects.list
        calls['users'] = self._clients.identity_manager_api.identity.users.list
        calls['instance_profiles'] = self._clients.identity_manager_api.identity.instance_profiles.list
        # Snapshots
        calls['snapshots'] = self._clients.snapshot_manager_api.snapshots.list
        calls['remote_snapshots'] = self._clients.snapshot_manager_api.remote_snapshots.list
        # Protection groups
        calls['protection_groups'] = self._clients.protection_api.protection.groups.list
        calls['protection_memberships'] = self._clients.protection_api.protection.memberships.list
        # Auto Scaling Groups
        calls['auto_scaling_groups'] = self._clients.asg_api.autoscaling_groups.groups.list
        calls['auto_scaling_launch_configurations'] = self._clients.asg_api.autoscaling_groups.launch_configurations.list
        calls['auto_scaling_scaling_policy'] = self._clients.asg_api.autoscaling_groups.scaling_policy.list
        calls['auto_scaling_scheduled_actions'] = self._clients.asg_api.autoscaling_groups.scheduled_actions.list
        # Container Registries
        calls['registries'] = self._clients.crs_api.crs.registry.list
        # DBC
        calls['dbc_clusters'] = self._clients.dbc_api.dbc.clusters.list
        calls['dbc_nodes'] = self._clients.dbc_api.dbc.nodes.list
        calls['dbc_parameter_groups'] = self._clients.dbc_api.dbc.parameter_groups.list
        # DBS
        calls['dbs_instances'] = self._clients.dbs_api.dbs.instance.list
        calls['dbs_parameter_groups'] = self._clients.dbs_api.dbs.parameter_group.list
        calls['dbs_snapshots'] = self._clients.dbs_api.dbs.snapshot.list
        calls['dbs_subnet_groups'] = self._clients.dbs_api.dbs.subnet_group.list
        # LBAAS
        calls['load_balancers'] = self._clients.lbaas_api.lbaas.load_balancers.list
        calls['lbaas_listeners'] = self._clients.lbaas_api.lbaas.listeners.list
        return calls

    def _load_clients(self, credentials):  # pylint: disable=too-many-locals
        from nodedapi_client.client import Client as NodedAPIlient
        from snapshot_manager_client.client import Client as SnapshotManagerClient
        from vm_manager_client.client import Client as VmManagerClient
        from vpc_backend_client.client import Client as VpcBackendClient
        from route53_client.client import Client as Route53Client
        from identity_manager_client.client import Client as IdentityManagerClient
        from autoscaling_groups_client.client import Client as AsgClient
        from crs_manager_client.client import Client as CrsClient
        from dbc_manager_client.client import Client as DbcClient
        from dbs_manager_client.client import DBSManagerClient
        from engine_manager_client.client import Client as EngineManagerClient
        from external_endpoint_manager_client.client import Client as EemClient
        from hot_upgrade_client.client import Client as HuClient
        from lbaas_client.client import Client as LbaasClient
        from image_manager_client.client import Client as ImageManagerClient
        from stratonet_frontend_client.client import Client as SnfClient
        from volume_manager_client.client import Client as VolumeManagerClient
        from melet_api_client.client import Client as MeleteApiClient
        from protection_client.client import Client as ProtectionClient
        self._clients.noded_api = NodedAPIlient(headers=credentials.headers).api.v2
        self._clients.vm_manager_api = VmManagerClient(headers=credentials.headers).api.v2.compute
        self._clients.volume_manager_api = VolumeManagerClient(headers=credentials.headers).api.v3
        self._clients.vpc_manager_api = VpcBackendClient(headers=credentials.headers).api.v2
        self._clients.melet_api = MeleteApiClient(headers=credentials.headers).api.v2
        self._clients.protection_api = ProtectionClient(headers=credentials.headers).api.v3
        self._clients.snapshot_manager_api = SnapshotManagerClient(headers=credentials.headers).api.v3
        self._clients.route53_api = Route53Client(headers=credentials.headers).api.v2
        self._clients.identity_manager_api = IdentityManagerClient(headers=credentials.headers).api.v2
        self._clients.asg_api = AsgClient(headers=credentials.headers).api.v2
        self._clients.crs_api = CrsClient(headers=credentials.headers).api.v2
        self._clients.dbc_api = DbcClient(headers=credentials.headers).api.v2
        self._clients.dbs_api = DBSManagerClient(headers=credentials.headers).api.v2
        self._clients.engine_manager_api = EngineManagerClient(headers=credentials.headers).api.v2
        self._clients.external_endpoint_api = EemClient(headers=credentials.headers).api.v2
        self._clients.hot_upgrade_api = HuClient(headers=credentials.headers).api.v2
        self._clients.lbaas_api = LbaasClient(headers=credentials.headers).api.v2
        self._clients.image_manager_api = ImageManagerClient(headers=credentials.headers).api.v2
        self._clients.stratonet_api = SnfClient(headers=credentials.headers).api.v2

    def collect_logical_inventory(self, credentials):
        failures = {}
        logical_data = OrderedDict()
        self._load_clients(credentials)
        calls = self._load_calls()

        for object_name, call in calls.iteritems():
            logger.debug("loading %s", format(object_name))
            logical_data[object_name], err = self._call_list(object_name, call)
            if err:
                failures[object_name] = err
        logical_data['rrsets'] = dict()
        if isinstance(logical_data.get('zones'), dict) and 'zones' in logical_data['zones']:
            logical_data['zones'] = logical_data['zones'].zones
            if logical_data['zones']:
                for zone in logical_data['zones']:
                    logical_data['rrsets'][zone.id], err = self._call_list('rrset for {}'.format(zone.id),
                                                                           (self._clients.route53_api.route53.rrset.get,
                                                                            dict(zone_id=zone.id)))
                    if err:
                        failures['zone_{}'.format(zone.id)] = err
        if isinstance(logical_data.get('system_zones'), dict) and 'zones' in logical_data['system_zones']:
            logical_data['system_zones'] = logical_data['system_zones'].zones
            if logical_data['system_zones']:
                for zone in logical_data['system_zones']:
                    logical_data['rrsets'][zone.id], err = self._call_list('rrset for {}'.format(zone.id),
                                                                           (self._clients.route53_api.route53.rrset.get,
                                                                            dict(zone_id=zone.id)))
                    if err:
                        failures['zone_{}'.format(zone.id)] = err

        return logical_data, failures

    @staticmethod
    def _call_list(object_name, call):
        try:
            if isinstance(call, tuple):
                return call[0](**call[1]), False
            else:
                return call(), False
        except Exception as ex:  # pylint: disable=broad-except
            return 'error extracting {}: {}'.format(object_name, str(ex)), True


def main():
    parser = argparse.ArgumentParser(description="Cluster state dump")
    parser.add_argument("--output", help="Output file", type=str, default="logical_inventory.json", dest='local_file')
    parser.add_argument('-v', '--verbose', help="Show debug log", action='store_true', default=False)
    args = parser.parse_args()
    if args.verbose:
        inspectorlogger.set_level(logging.DEBUG)

        inspectorlogger.set_level(logging.INFO)
    local_runner = runner.Runner()
    datalayer_tool = DatalayerTools(local_runner)
    datalayer_tool.report_logical_inventory(local_file=args.local_file)
    return 0


if __name__ == '__main__':
    sys.exit(main())
