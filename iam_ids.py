import boto.iam
import ConfigParser
import sys
import os.path
import argparse
import idsConfig
import idsNotify

list_user=""

parser = argparse.ArgumentParser(description='IAM intrusion detection')
parser.add_argument("-l", "--list-user", action="store", dest="list_user", help="list trusted user file")
args = parser.parse_args()

try:
    conn = boto.iam.connection.IAMConnection(aws_access_key_id = idsConfig.id, aws_secret_access_key = idsConfig.key)
    data = conn.get_all_users()
except Exception as e:
    idsNotify.send_alert("AWS IDS: \n"+str(e))
    sys.exit(1)

user_list=[]
for user in data['list_users_response']['list_users_result']['users']:
    user_list.append(user['user_name'])

user_list_file = ConfigParser.ConfigParser()
user_list_file.read(os.path.expanduser(args.list_user))
local_user_names = user_list_file.get("verified_users", "unames", raw=True).split(',')
diff = list(set(user_list) - set(local_user_names))
if len(diff) > 0:
    idsNotify.send_alert("AWS IDS: \nUnknown user detected: "+diff)
