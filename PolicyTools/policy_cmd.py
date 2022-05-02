#!/usr/bin/python

import importlib
import sys
import json
import uuid
import os
import argparse

CLI = '/usr/bin/symp -k '
#CLI = '/usr/bin/symp -k --debug -v '

AWS_PREFIX = '{ "Version": "2012-10-17", "Statement": '
AWS_POSTFIX = ' }'

AWS_POLICY = 'aws-policy'
STRATO_POLICY = 'strato-policy'

'''

Updates the specified AWS policy.

positional arguments:
  policy_id             The ID of the policy to delete

optional arguments:
  -h, --help            show this help message and exit
  --name NAME           The name of the policy
  --policy-document POLICY_DOCUMENT
                        The JSON policy document for the new policy
                        Should be of the following format: '{"Statement": [{"Action": [<actions>], "Effect": "Allow", "Resource": ["*"]}]}'
  --description DESCRIPTION
                        A friendly description of the policy




'''

def parse_arguments():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("account", help="Your zCompute domain/account name")
    parser.add_argument("project", help="project name to log into")
    parser.add_argument("user", help="Your zCompute account admin user")
    parser.add_argument("password", help="zCompute password")
    parser.add_argument("endpoint", help="IP or the domain for zCompute")
    parser.add_argument("cmd", choices=['create', 'update','list','get','del','delete'], 
                        help="Operation to perform. \n"
                             "For create: --name and --filename are amandatory, --description and --domain-id are optional\n"
                             "For update, --filename and --id are mandatory\n"
                             "For list, --filter is mandatory\n"
                             "For get, --id is mandatory\n"
                             "For del, --id is mandatory"
                        )
    parser.add_argument("--zpolicy", help="Work with Zadara policies", dest='policy', action='store_const', const='strato-policy', default='aws-policy', required=False)
    parser.add_argument("--mfa-secret", help="Multi-Factor Authentication secret obtained when setting the MFA code", required=False)
    parser.add_argument("--id", help="Policy UUID, required only for policy update", required=False)
    parser.add_argument("--filename", help="json file containing the policy", required=False)
    parser.add_argument("--zformat", help="The policy file is in the shorter Zadara format", action='store_true', required=False)
    parser.add_argument("--description", help="", default=False, required=False)
    parser.add_argument("--name", help="policy name", required=False)
    parser.add_argument("--domain-id", help="id of the domain/account if creating domain level policy. Relevant only for system admin", required=False)
    parser.add_argument("--filter", help="Filter policies by name or partial name in the list", required=False)
    return parser.parse_args()


if __name__ == "__main__":
    """ This is executed when run from the command line """
    args = parse_arguments()
    doc = ""
    if args.filename:
        doc = json.loads(file(args.filename, 'r').read())
        doc = json.dumps(doc)
        if args.zformat:
            doc = AWS_PREFIX + doc + AWS_POSTFIX

    command = " --url https://" + args.endpoint + "/" + " -d " + args.account + " -u " + args.user + " -p " + args.password + " " 
    command += " --project " + args.project + " " 
    command += " --mfa-secret " + args.mfa_secret + " " if args.mfa_secret else ""

    # This adds the policy 'aws-policy' (default) or 'strato-policy' to the command string        
    command += args.policy + " "

    if args.cmd == "create":
        if not args.name or not args.filename:
            print "policy name and policy file must be provided in the create command"
            sys.exit(1)
        command += "create "
        command += " --description \'" + args.description + "\' " if args.description else ""
        command += " --scope-id " + args.domain_id + " " if args.domain_id else ""
        command += args.name + " " + "\'" + doc + "\' "
        command += "domain" if args.domain_id or args.account not in ("cloud_admin", "cloud_ops", "cloud_msp") else "public"

    if args.cmd == "update":
        if not args.filename:
            print "must provide a policy filename"
            sys.exit(1)
        if not args.id:
            print "must provide the id of the policy to update"
            sys.exit(1)
        command += "update "
        command += "--policy-document \'" + doc + "\' " if args.filename else ""
        command+= args.id 

    if args.cmd == "list":
        command += "list "
    
    if args.cmd == "get":
        command += "get  "
        command+= args.id 

    if args.cmd in ("del","delete"):
        if not args.id:
            print "must provide the id of the policy to update"
            sys.exit(1)
        command += "remove " 
        command+= args.id 
        
        
    print command
    cmd_output = os.popen(CLI + command)
    output = cmd_output.readlines()
    for line in output:
        if not args.filter:
            print line.strip()
        elif args.filter.lower() in line.lower() or "scope_type" in line:
            print line.strip()
    

