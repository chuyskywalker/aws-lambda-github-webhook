import sys,os
sys.path.append(os.path.join(os.path.dirname(__file__), "vendor"))

import json, boto3, hmac, hashlib, yaml, github
from pykwalify.core import Core


def invoke_secondary(hookname, hookconfig, originalbody):
    client = boto3.client('lambda')
    originalbody['_secondary'] = hookname
    originalbody['_hookconfig'] = hookconfig
    print "Sending secondary call {} with config {}".format(hookname, json.dumps(hookconfig))
    print client.invoke(
        FunctionName='tf_gh_check_function_secondary',
        InvocationType='Event',
        Payload=json.dumps(originalbody)
    )


def incoming(event, context):
    """
    Validate the incoming event from the API gateway
    """

    print json.dumps(event)

    # validate the secret
    if not validate_secret(event['headers'].get('X-Hub-Signature'), event['body']):
        return {"body": json.dumps({"error": "invalid signature"}), "statusCode": 403}

    # Get the hook info
    # todo: we trust github to send valid json, but should add a try/catch anyway
    hookdata = json.loads(event['body'])

    # this will only work, for now, with hooks that include repo information
    if 'repository' not in hookdata:
        print "No repository in the hook, no processing"
        return {"body": json.dumps({"error": "unsupported hook type; missing repository information"}), "statusCode": 501}

    repo = hookdata['repository']['full_name']

    # Now, we fetch the config from the repo to see what hooks we should trigger
    try:
        hooks_yml = get_github().get_repo(repo, lazy=True).get_file_contents('.hooks.yml')
        print "Fetched .hooks.yml from repo {}".format(repo)
    except github.GithubException:
        print "Missig .hooks.yml on repo {}".format(repo)
        return {"body": json.dumps({"error": "no .hooks.yml present"}), "statusCode": 501}

    # todo: safe load try/catch needed here
    hook_config = yaml.safe_load(hooks_yml.decoded_content)

    # Schema based validation
    c = Core(source_data=hook_config, schema_files=[os.path.join(os.path.dirname(__file__), "hooks.schema.yml")])
    c.validate(raise_exception=False)
    if len(c.validation_errors) > 0:
        print c.validation_errors
        return {"body": json.dumps({"error": "invalid hooks configuration"}), "statusCode": 501}

    ghevent = event['headers'].get('X-GitHub-Event', '')

    # Check hooks!

    # we _always_ run the .hooks.yml schema validation check
    if (ghevent == 'pull_request' and
        'action' in hookdata and hookdata["action"] in ["opened", "synchronize", "reopened"]):
        invoke_secondary('hooks_schema', {}, hookdata)

    # yml validation is only on pull requests (re)open|sync
    if ('yml_validation' in hook_config['hooks'] and
        ghevent == 'pull_request' and
        'action' in hookdata and hookdata["action"] in ["opened", "synchronize", "reopened"]
       ):
        invoke_secondary('yml_validation', hook_config['hooks']['yml_validation'], hookdata)

    # A silly one that always passes on pull requests (re)open|sync
    if ('always_pass' in hook_config['hooks'] and
        ghevent == 'pull_request' and
        'action' in hookdata and hookdata["action"] in ["opened", "synchronize", "reopened"]
       ):
        invoke_secondary('always_pass', hook_config['hooks']['always_pass'], hookdata)

    # approval count triggers on pr (re)open as well as pr_review events
    if ('approval_count' in hook_config['hooks'] and (
         (ghevent == 'pull_request' and
          'action' in hookdata and hookdata["action"] in ["opened", "reopened"])
         or
         (ghevent == 'pull_request_review' and
          'action' in hookdata and hookdata["action"] in ["submitted", "edited"])
        )
       ):
        invoke_secondary('approval_count', hook_config['hooks']['approval_count'], hookdata)

    # all done!
    return {"body": json.dumps({"message": "Thanks"}), "statusCode": 200}


def secondary(event, context):
    """
    Evaluate a secondary call
    """
    print json.dumps(event)
    print "Processing secondary call..."

    if '_secondary' not in event: # wtf
        return

    print "Secondary call is {} with config {}".format(event['_secondary'], json.dumps(event['_hookconfig']))

    if event['_secondary'] == 'hooks_schema':
        hooks_schema(event)
    elif event['_secondary'] == 'yml_validation':
        yml_validation(event)
    elif event['_secondary'] == 'approval_count':
        approval_count(event)
    elif event['_secondary'] == 'always_pass':
        always_pass(event)
    else:
        # huh
        print "Unsupported method"

    print "Secondary call for {} complete".format(event['_secondary'])


def always_pass(event):
    """
    Add a passing status check to a pr
    """
    repofullname = event['repository']['full_name']
    commitsha = event['pull_request']['head']['sha']
    get_github()\
        .get_repo(repofullname)\
        .get_commit(commitsha)\
        .create_status('success', description="You're awesome!", context="always_pass")


def approval_count(event):
    """
    Add a pass if the # of approvers is >= config value
    """
    # todo: actually imlement
    repofullname = event['repository']['full_name']
    commitsha = event['pull_request']['head']['sha']
    get_github()\
        .get_repo(repofullname)\
        .get_commit(commitsha)\
        .create_status('success', description="Approvals all found", context="approval_count")


def yml_validation(event):
    """
    Scan all specified paths and confirm that the yml files are loadably safe
    """
    # todo: actually imlement
    repofullname = event['repository']['full_name']
    commitsha = event['pull_request']['head']['sha']
    get_github()\
        .get_repo(repofullname)\
        .get_commit(commitsha)\
        .create_status('success', description="All yml files are valid", context="yml_validation")


def hooks_schema(event):
    """
    Check if the PR has any changed to .hooks.yml and validate the file
    """
    # todo: actually imlement
    repofullname = event['repository']['full_name']
    commitsha = event['pull_request']['head']['sha']
    get_github()\
        .get_repo(repofullname)\
        .get_commit(commitsha)\
        .create_status('success', description=".hooks.yml valid!", context="hooks_schema")


def get_github():
    with open(os.path.join(os.path.dirname(__file__), "ghtoken.txt")) as f:
        ghtoken = f.read().strip()
    return github.Github(ghtoken)


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
#     g = github.Github(ghtoken)
#     try:
#         hooks = g.get_repo('chuyskywalker/lambchops').get_file_contents('.hooks.ymlx')
#         print hooks.decoded_content
#     except github.GithubException:
#         print "no file"
#
#
# # For local testing
# if __name__ == "__main__":
#     main()
