import sys
sys.path.append('./vendor')

import json
from github import Github


def handler(event, context):
    print json.dumps(event)
    print "Log stream name:" + context.log_stream_name
    print "Log group name:" + context.log_group_name
    return {"body": json.dumps({ "message": "Thanks"}), "statusCode": 200}

ghtoken = '773db8da0f6e543136d0b2ba8beebda2e02c291e'


def main():
    g = Github(ghtoken)
    for repo in g.get_user().get_repos():
        print repo.name

if __name__ == "__main__":
    main()

