import sys,os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vendor"))

import boto3, json, logging, hmac, hashlib, yaml, github
from pykwalify.core import Core
from util.tfgithub import get_github
from checks import all as all_checks

logger = logging.getLogger(__name__)


def incoming(event, context):
    """
    Validate the incoming event from the API gateway
    """

    print json.dumps(event)  # not logger.info() so it doesn't show up in logview itself :)

    # validate the secret
    if not validate_secret(event['headers'].get('X-Hub-Signature'), event['body']):
        return {"body": json.dumps({"error": "invalid signature"}), "statusCode": 403}

    # Get the hook info
    try:
        hookdata = json.loads(event['body'])
    except Exception:
        logger.error("Failed to decode json")
        return {"body": json.dumps({"error": "json decode failure"}), "statusCode": 500}

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

    try:
        hook_config = yaml.safe_load(hooks_yml.decoded_content)
    except Exception:
        logger.error("Failed to decode hook yaml")
        return {"body": json.dumps({"error": "hook yaml failure"}), "statusCode": 500}

    # Schema based validation
    c = Core(source_data=hook_config, schema_files=[os.path.join(os.path.dirname(__file__), "..", "hooks.schema.yml")])
    c.validate(raise_exception=False)
    if len(c.validation_errors) > 0:
        logger.error(c.validation_errors)
        return {"body": json.dumps({"error": "invalid hooks configuration"}), "statusCode": 501}

    ghevent = event['headers'].get('X-GitHub-Event', '')

    # Check hooks!
    logger.info("Qualifying checks:")
    for name, check in all_checks.get_all_checks().iteritems():
        check_config = check.qualify(ghevent, hookdata, hook_config)
        if check_config:
            logger.info("- {} passed qualify, invoking secondary call".format(name))
            invoke_secondary(name, check_config, event)
        else:
            logger.info("- {} did not qualify, skipping".format(name))

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