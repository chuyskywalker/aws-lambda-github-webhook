import sys,os
sys.path.append(os.path.join(os.path.dirname(__file__), "vendor"))

import json
from github import Github


def handler(event, context):
    print json.dumps(event)
    print "Log stream name:" + context.log_stream_name
    print "Log group name:" + context.log_group_name
    return {"body": json.dumps({ "message": "Thanks"}), "statusCode": 200}


def main():
    with open(os.path.join(os.path.dirname(__file__), "ghtoken.txt")) as f:
        ghtoken = f.read().strip()
    g = Github(ghtoken)
    for repo in g.get_user().get_repos():
        print repo.name

# For local testing
if __name__ == "__main__":
    main()
