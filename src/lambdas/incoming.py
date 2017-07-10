import sys,os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vendor"))

import boto3, json, logging, hmac, hashlib, yaml, github
from pykwalify.core import Core
from util.tfgithub import get_github

logger = logging.getLogger()


def incoming(event, context):
    """
    Validate the incoming event from the API gateway
    """

    print json.dumps(event)  # not logger.info() so it doesn't show up in logview itself :)

    # validate the secret
    if not validate_secret(event['headers'].get('X-Hub-Signature'), event['body']):
        return {"body": json.dumps({"error": "invalid signature"}), "statusCode": 403}

    # Get the hook info
    # todo: we trust github to send valid json, but should add a try/catch anyway
    hookdata = json.loads(event['body'])

    # this will only work, for now, with hooks that include repo information
    if 'repository' not in hookdata:
        logger.error("No repository in the hook, no processing")
        return {"body": json.dumps({"error": "unsupported hook type; missing repository information"}), "statusCode": 501}

    repo = hookdata['repository']['full_name']

    # Now, we fetch the config from the repo to see what hooks we should trigger
    try:
        hooks_yml = get_github().get_repo(repo, lazy=True).get_file_contents('.hooks.yml')
        logger.info("Fetched .hooks.yml from repo {}".format(repo))
    except github.GithubException:
        logger.error("Missig .hooks.yml on repo {}".format(repo))
        return {"body": json.dumps({"error": "no .hooks.yml present"}), "statusCode": 501}

    # todo: safe load try/catch needed here
    hook_config = yaml.safe_load(hooks_yml.decoded_content)

    # Schema based validation
    c = Core(source_data=hook_config, schema_files=[os.path.join(os.path.dirname(__file__), "..", "hooks.schema.yml")])
    c.validate(raise_exception=False)
    if len(c.validation_errors) > 0:
        logger.error(c.validation_errors)
        return {"body": json.dumps({"error": "invalid hooks configuration"}), "statusCode": 501}

    ghevent = event['headers'].get('X-GitHub-Event', '')

    # Check hooks!

    # we _always_ run the .hooks.yml schema validation check
    if (ghevent == 'pull_request' and
        'action' in hookdata and hookdata["action"] in ["opened", "synchronize", "reopened"]):
        invoke_secondary('hooks_schema', {}, event)

    # yml validation is only on pull requests (re)open|sync
    if ('yml_validation' in hook_config['hooks'] and
        ghevent == 'pull_request' and
        'action' in hookdata and hookdata["action"] in ["opened", "synchronize", "reopened"]
       ):
        invoke_secondary('yml_validation', hook_config['hooks']['yml_validation'], event)

    # A silly one that always passes on pull requests (re)open|sync
    if ('always_pass' in hook_config['hooks'] and
        ghevent == 'pull_request' and
        'action' in hookdata and hookdata["action"] in ["opened", "synchronize", "reopened"]
       ):
        invoke_secondary('always_pass', hook_config['hooks']['always_pass'], event)

    # approval count triggers on pr (re)open as well as pr_review events
    if ('approval_count' in hook_config['hooks'] and (
         (ghevent == 'pull_request' and
          'action' in hookdata and hookdata["action"] in ["opened", "synchronize", "reopened"])
         or
         (ghevent == 'pull_request_review' and
          'action' in hookdata and hookdata["action"] in ["submitted", "edited"])
        )
       ):
        invoke_secondary('approval_count', hook_config['hooks']['approval_count'], event)

    # all done!
    return {"body": json.dumps({"message": "Thanks"}), "statusCode": 200}


def invoke_secondary(hookname, hookconfig, original_event):
    client = boto3.client('lambda')
    original_event['_secondary'] = hookname
    original_event['_hookconfig'] = hookconfig
    logger.info("Sending secondary call {} with config {}".format(hookname, json.dumps(hookconfig)))
    logger.info(client.invoke(
        FunctionName='tf_gh_check_function_secondary',
        InvocationType='Event',
        Payload=json.dumps(original_event)
    ))


def validate_secret(header_signature, msg):
    with open(os.path.join(os.path.dirname(__file__), "..", "ghsecret.txt")) as f:
        secret = f.read().strip()

    if header_signature is None:
        logger.error("Header signature missing")
        return False

    sha_name, signature = header_signature.split('=')
    if sha_name != 'sha1':
        logger.error("Header signature not signed with sha1")
        return False

    # HMAC requires the key to be bytes, but data is string
    mac = hmac.new(str(secret), msg=msg, digestmod=hashlib.sha1)

    # Get ours vs. theirs
    expected = str(mac.hexdigest())
    received = str(signature)

    # Timing attack secure comparison
    matches = hmac.compare_digest(expected, received)

    if not matches:
        logger.error("Header signature ({}) does not match expected ({})".format(received, expected))

    return matches