import sys,os
sys.path.append(os.path.join(os.path.dirname(__file__), "vendor"))

import json
from github import Github
import boto3, hmac, hashlib


def incoming(event, context):
    """
    Validate the incoming event from the API gateway
    """

    print json.dumps(event)

    # validate the secret
    if not validate_secret(event['headers'].get('X-Hub-Signature'), event['body']):
        print {"body": json.dumps({"error": "invalid signature"}), "statusCode": 403}

    # validate the payload is something we care about
    if not event['headers'].get('X-GitHub-Event') == 'pull_request':
        print {"body": json.dumps({"message": "thanks, but no thanks"}), "statusCode": 200}

    hookdata = json.loads(event['body'])
    client = boto3.client('lambda')

    # See if we want it and trigger other lambdas
    if 'action' in hookdata and hookdata["action"] == "opened":
        print client.invoke(
            FunctionName='tf_gh_check_function_opening_comment',
            InvocationType='Event',
            Payload=event['body']
        )

    if 'action' in hookdata and hookdata["action"] in ["opened", "synchronize", "reopened"]:
        print client.invoke(
            FunctionName='tf_gh_check_function_passing_status',
            InvocationType='Event',
            Payload=event['body']
        )

    # all done!
    return {"body": json.dumps({"message": "Thanks"}), "statusCode": 200}


def opening_comment(event, context):
    """
    Adds an opening comment on GH pr's
    """
    print json.dumps(event)
    repofullname = event['repository']['full_name']
    issuenum = event['number']
    get_github()\
        .get_repo(repofullname)\
        .get_issue(issuenum)\
        .create_comment("You've been hooked!")


def passing_status(event, context):
    """
    Add a passing status check to a pr
    """
    print json.dumps(event)
    repofullname = event['repository']['full_name']
    commitsha = event['pull_request']['head']['sha']
    get_github()\
        .get_repo(repofullname)\
        .get_commit(commitsha)\
        .create_status('success', description="You're awesome!", context="lambda-hook")


def get_github():
    with open(os.path.join(os.path.dirname(__file__), "ghtoken.txt")) as f:
        ghtoken = f.read().strip()
    return Github(ghtoken)


def validate_secret(header_signature, msg):
    with open(os.path.join(os.path.dirname(__file__), "ghsecret.txt")) as f:
        secret = f.read().strip()

    if header_signature is None:
        return False

    sha_name, signature = header_signature.split('=')
    if sha_name != 'sha1':
        return False

    # HMAC requires the key to be bytes, but data is string
    mac = hmac.new(str(secret), msg=msg, digestmod=hashlib.sha1)

    # Timing attack secure comparison
    return hmac.compare_digest(str(mac.hexdigest()), str(signature))


# def main():
#     with open(os.path.join(os.path.dirname(__file__), "ghtoken.txt")) as f:
#         ghtoken = f.read().strip()
#     g = Github(ghtoken)
#     for repo in g.get_user().get_repos():
#         print repo.name
#
# # For local testing
# if __name__ == "__main__":
#     main()
