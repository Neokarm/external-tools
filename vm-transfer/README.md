Tool for copying zCompute VMs from cluster to cluster (using R7+ DR protection group, or manual volumes)
```
usage: zvm_transfer.py [-h] [--no-dry-run] [--dry-run] [--vm VM] [--vpc VPC]
                       [--filename FILENAME] [--skip-sg] [--ignore-vm-state]
                       [--ipdb] [--also-mirror-volumes]
                       [--volume-id VOLUME_ID] [--volume-name VOLUME_NAME]
                       [--use-cc-passthrough] [--version]
                       {migrate,migrate_all,migrate_vpc_vms,manage,unmanage}

positional arguments:
  {migrate,migrate_all,migrate_vpc_vms,manage,unmanage}
                        Operation to perform. one of: migrate (migrate a VM),
                        migrate_vpc_vms (migrate all user VMs in a VPC),
                        migrate_all (migrate a list of VMs - from a filename),
                        manage (manage a single volume), unmanage (unmanage a
                        single volume)

optional arguments:
  -h, --help            show this help message and exit
  --no-dry-run          Run in non dry run mode
  --dry-run             Run in dry run mode (Default)
  --vm VM               VM uuid/name
  --vpc VPC             VPC uuid
  --filename FILENAME   filename with names/uuid of VMs to migrate
  --skip-sg             skip security-groups
  --ignore-vm-state     Ignore source VM state when transferring VM definition
  --ipdb                give me ipdb with clients and continue
  --also-mirror-volumes
                        By default only look for mirror jobsthis flag allow to
                        use volumes from broken mirror jobs
  --volume-id VOLUME_ID
                        Just manage volume
  --volume-name VOLUME_NAME
                        Name for managed volume
  --use-cc-passthrough  Access VPSA using CC pass through mode (when VPSA is
                        not directly accessible
  --version             show program's version number and exit
```


* The tools try to recover previous failure - it should be safe to re-run it after a the error was fixed
(e.g. connectivity to VPSA, wrong network name/security groups, etc)

* In order to use DR protection-group mirror job snapshot you must provide either the VPSA API address
or the CCVM API address (if the VPSA API address is not publicly exposed)_.
If the CCVM API address is used the VPSA API Tunnel option should be enabled in the CCVM, and the flag use-cc-passthrough
should be provided in the the command line

* By default the tool run in dry run mode, and only validate that the copy is possible
In order to perform the copy - add --no-dry-run to the command line

* If the SG names do not match between cluster you can choose to skip SG configuration and do it manually after the VM is created by adding --skip-sg flag
In such case the default SG will be attached to all of the vNIC assigned to the VM

* The tool select the volumes to attach to the VM according to the following priority
- a volume in the destination cluster with the expected volume display name ("neokarm-volume_<volume_id>")
- a mirror job in the destination cluster with the expected mirror job display name ("neokarm_mirror_<volume_id>_uuid_uuid")
  If there are multiple mirror jobs one will be randomly selected
  After the mirror is broken the volume display name will be renamed to "neokarm-volume_<volume_id>".
  if the operation failed for some reason the next time the volume with display name "neokarm-volume_<volume_id>" will be used
- If the --also-mirror-volumes flag is used the tool will also search for a volume which is a result of a mirror job break.
  This flag is relevant if the mirror_job break succeeded but the volume rename failed for some reason

* Credential Setup:
 The tool receive its credential using environment variable - first set your environment according to the "env" example file
 The tool need to run with admin role (as the user credential), you can use any account/project/user as long it has admin role
 Please note that the SRC_PROJECT_ID & DST_PROJECT_ID refer to the project use for login in each cloud while
 SRC_TRANSFER_PROJECT_ID and DST_TRANSFER_PROJECT_ID refer to the migrated VMs projects

* The tool support 5 different operations
  * migrate - migrate a single VM according to it name or UUID
  If there are multiple VMs with the same name in the source project you must specify the VM UUID
  You can also specify the VPC name or ID in the project to narrow the filter for VM selection by name
  * migrate_all - migrate all VMs in a single project
  * migrate_vpc_vms - migrate all VMs in a single VPC
  * manage - manage a VPSA volume in zCompute
  * unmanage - stop managing a VPSA volume in zCompute without deleting the volume


