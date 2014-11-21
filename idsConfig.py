import os.path
import ConfigParser

check = os.path.isfile(os.path.expanduser('~/.aws_ids.conf'))
if cmp(check,False) == 0:
    print "~/.aws_ids.conf is missing"
    sys.exit(1)
config = ConfigParser.ConfigParser()
config.read(os.path.expanduser('~/.aws_ids.conf'))
id = config.get("AWS", "consumer_key", raw=True)
key = config.get("AWS", "consumer_secret", raw=True)
sqlite_path = config.get("SQLITE", "path", raw=True)
