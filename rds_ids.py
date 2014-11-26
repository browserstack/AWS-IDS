import ConfigParser
import sys
import os.path
import argparse
import boto.rds
import boto.ec2
import netaddr
import idsConfig
import idsNotify

list_ips = []
list_instances = []

def get_all_IPs(conn, region):
    sec_grps = conn.get_all_dbsecurity_groups()
    for grp in sec_grps:
        for ip in grp.ip_ranges:
            IPs = list(netaddr.IPNetwork(ip.cidr_ip))
            for IP in IPs:
                list_ips.append(str(IP))
        for ec2_group in grp.ec2_groups:
            try:
                conn_ec2 = boto.ec2.connect_to_region(region, aws_access_key_id = idsConfig.id, aws_secret_access_key = idsConfig.key)
                for server in conn_ec2.get_all_security_groups(group_ids=[ec2_group.EC2SecurityGroupId])[0].instances():
                    if server.state == "running":
                        list_ips.append(server.ip_address)
                        list_ips.append(server.private_ip_address)
            except Exception as e:
                idsNotify.send_alert("AWS IDS: \n"+str(e))
                sys.exit(1)
    return list(set(list_ips))

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument("-r", "--region", action="store", dest="region", help="region in which rds is running")
parser.add_argument("-l", "--list-rds", action="store", dest="list_rds", help="list trusted rds data file")
args = parser.parse_args()

try:
    conn = boto.rds.connect_to_region(args.region, aws_access_key_id = idsConfig.id, aws_secret_access_key = idsConfig.key)
    for db in conn.get_all_dbinstances():
        list_instances.append(db.id)
    ip_data = get_all_IPs(conn, args.region)
except Exception as e:
    idsNotify.send_alert("AWS IDS: \n"+str(e))
    sys.exit(1)

rds_trusted_file = ConfigParser.ConfigParser()
rds_trusted_file.read(os.path.expanduser(args.list_rds))
trusted_instances = rds_trusted_file.get("verified_instances", "ids", raw=True).split(',')
trusted_ips = rds_trusted_file.get("verified_ips", "ips", raw=True).split(',')

diff = list(set(list_ips) - set(trusted_ips))
if len(diff) > 0:
    idsNotify.send_alert("AWS IDS: \nUnknown IP in RDS: "+diff)

diff = list(set(list_instances) - set(trusted_instances))
if len(diff) > 0:
    idsNotify.send_alert("AWS IDS: \nUnknown instance in RDS: "+diff)

