AWS-IDS
=======

Simple Amazon Web Services Intrusion Detection System

Requirements
* python-boto
* sqlite3
* netaddr
 
sqlite3 schema:
CREATE TABLE members (agent varchar(40), user_key varchar(30), app_key varchar(30), email_id varchar(60) unique);

