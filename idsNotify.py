import urllib
import urllib2
import sqlite3
import os.path
import ast
import idsConfig

def send_pushover(user, token, message):
    urllib2.urlopen("https://api.pushover.net/1/messages.json",urllib.urlencode({"token":token,"user":user,"message":message}))

ACTIONS = {"send_pushover": send_pushover}

def send_alert(message):
    conn = sqlite3.connect(idsConfig.sqlite_path)
    c = conn.cursor()

    for member in c.execute("select * from members"):
	ACTIONS[member[0]](member[1], member[2], message)
