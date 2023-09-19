Tool for cleanup of zCompute snapshots (Volume snapshots or VM snapshots) from cluster
```
./snapshots-cleanup.py --help
usage: snapshots-cleanup.py [-h] [--no-dry-run] [--dry-run] [--no-verify-ssl]
                            [--print-all] [--only-volumes] [--only-vms]
                            [--protect-vm PROTECT_VMS]
                            [--exclude-pg EXCLUDED_PGS]
                            [--protect-volume PROTECT_VOLUMES]
                            [--continue-on-error] [--ipdb] [--mfa]
                            [--online-config] [--temp-token] [--write-config]
                            [--overwrite-config] [--write-passwords]
                            [--retention-days RETENTION_DAYS] [--version]
                            
                            {snapshots-status,clean-snapshots-in-error,purge-auto-snapshots,purge-manual-snapshots,purge-all-snapshots}

positional arguments:
  {snapshots-status,clean-snapshots-in-error,purge-auto-snapshots,purge-manual-snapshots,purge-all-snapshots}
                        Operation to perform. one of: migrate (migrate a VM),
                        migrate_vpc_vms (migrate all user VMs in a VPC),
                        migrate_all (migrate a list of VMs - from a filename),
                        manage (manage a single volume), unmanage (unmanage a
                        single volume)

optional arguments:
  -h, --help            show this help message and exit
  --no-dry-run          Run in non dry run mode
  --dry-run             Run in dry run mode (Default)
  --no-verify-ssl       Skip SSL connection verification
  --print-all           Print all snapshots to the log
  --only-volumes        Perform only volume snapshots retention
  --only-vms            Perform only VM snapshots retention
  --protect-vm PROTECT_VMS
                        VM IDs to protect from retention (can appear multiple
                        times)
  --exclude-pg EXCLUDED_PGS
                        Protection group IDs to protect from retention (can
                        appear multiple times)
  --protect-volume PROTECT_VOLUMES
                        Volume IDs to protect from retention (can appear
                        multiple times)
  --continue-on-error   Continue on error
  --ipdb                Drop to ipdb debugger before login
  --mfa                 Ask for MFA code
  --online-config       Read login parameters interactively
  --temp-token          Do not write login token to the cred_env file
  --write-config        Write env file ('cred_env' in local directory) with login
                        parameters
  --overwrite-config    Overwrite env file ('cred_env' in local directory) with
                        login parameters
  --write-passwords     Write passwords to cred_env file
  --retention-days RETENTION_DAYS
                        Number of days for retention period
  --version             show program's version number and exit
```


* The tool will go over all Volume and VM snapshots in the cluster (visible to the user logged in) and will allow retention of snapshots in error or older than a specified age (by default 14 days
* The tool can be used by any user. When used by a user with admin role it will perform work on all cluster snapshots. 
* By default the tool run in dry run mode, and only output statistics on current snapshots status and the number of snapshots that will be deleted 
* In order to perform the retention operation - add `--no-dry-run` to the command line
* In order to list all snapshots relevant for retention add `--print-all` to the command line

* Credential Setup:
 The tool can receive its login details/credentials interactively or by using environment variables
  * The following parameters are read from the environment
    * DST_CLUSTER_IP - (*mandatory*) - IP/DNS of the cluster
    * DST_LOGIN_ACCOUNT - (*mandatory*) - Account name to use for login
    * DST_LOGIN_PROJECT_NAME - (*mandatory*) - Project name to use for login
    * DST_LOGIN_USERNAME - (*mandatory*) - User name to use for login
    * DSP_LOGIN_PASSWORD - (*optional*) - Password to use for login (will be read from console if not provided)
    * DST_MFA_SECRET - (*optional*) - MFA Secret to use for creation of TOTP code, use `--mfa` flag to interactively request for MFA code
    * DST_TOKEN - (*optional*) - zCompute token to use for login
  * In order to use the interactive mode add `--online-config` flag to the command line
  * The variable entered in interactive mode can be written to an environment file called `cred_env` and later use by using one of the --write-config or --overwrite-config flags
  * Password will not be written to the file you can use `--write-password` to change this behavior
  * The token received in the login process will be written to the `cred_env` file for further use (the file MUST be re-read using `source cred_env` before further invocation of the tool)
    
* The tool support the following operations:
  * snapshots-status - write statistics of cluster snapshots (use `--print-all` to print per snapshot detailed log)
  * clean-snapshots-in-error - delete all snapshots in error state, or in creating state for more than a day
  * purge-auto-snapshots - purge all snapshots (volumes and VMs) that were automatically generated by retention groups
  * purge-manual-snapshots - purge all snapshots (volumes and VMs) that were manually generated by user
  * purge-all-snapshots - purge all snapshots (volumes and VMs) - both manually and automatically generated

example output:
```
./snapshots-cleanup.py snapshots-status --exclude-pg 141a10ae-148f-48be-bdee-3735996d3e82 --no-verify-ssl
2023-09-19 06:34:03,719 [root] INFO       Logger initialized
2023-09-19 06:34:05,344 [root] INFO       Considering snapshot older than Tue Sep  5 06:34:05 2023 for retention
2023-09-19 06:34:06,360 [root] INFO       There are 0 Volumes to protect from retention
2023-09-19 06:34:06,360 [root] INFO       There are 56 Image snapshots
2023-09-19 06:34:06,360 [root] INFO       There are 0 Volume snapshots in error/error-creating state
2023-09-19 06:34:06,360 [root] INFO       There are 0 Volume snapshots in error creating state
2023-09-19 06:34:06,360 [root] INFO       There are 9 VM snapshots in error/error-creating state
2023-09-19 06:34:06,360 [root] INFO       There are 6 VM snapshots in error creating state
2023-09-19 06:34:06,360 [root] INFO       There are 86 VM Snapshots that will not be deleted because of protection
2023-09-19 06:34:06,360 [root] INFO       There are 76 Volume Snapshots that will not be deleted because of protection
2023-09-19 06:34:06,361 [root] INFO       There are 76 Volumes Snapshots to protect from retention due to triggering PG
2023-09-19 06:34:06,361 [root] INFO       There are 86 VM Snapshots to protect from retention due to triggering PG
2023-09-19 06:34:06,361 [root] INFO       There are 151 Volume snapshots older than retention time
2023-09-19 06:34:06,361 [root] INFO       There are 103 Automatic Volume snapshots older than retention time
2023-09-19 06:34:06,361 [root] INFO       There are 48 Manual Volume snapshots older than retention time
2023-09-19 06:34:06,361 [root] INFO       There are 73 VM Snapshots older than retention time
2023-09-19 06:34:06,361 [root] INFO       There are 52 Automatic VM Snapshots older than retention time
2023-09-19 06:34:06,361 [root] INFO       There are 21 Manual VM Snapshots older than retention time
```
