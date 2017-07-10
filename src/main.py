import sys,os
sys.path.append(os.path.join(os.path.dirname(__file__), "vendor"))

import json, boto3, hmac, hashlib, yaml, github, pyDes, base64, urllib, logging, datetime
from pykwalify.core import Core

logger = logging.getLogger()
logger.setLevel(logging.INFO)


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


def short_token():
    with open(os.path.join(os.path.dirname(__file__), "ghtoken.txt")) as f:
        ghtoken = f.read().strip()[0:24]
    return ghtoken


def encode_log_location(group, stream, reqid):
    val = json.dumps([group, stream, reqid])
    enc = pyDes.triple_des(short_token()).encrypt(val, padmode=pyDes.PAD_PKCS5)
    return base64.encodestring(enc)


def decode_log_location(base64id):
    dec = base64.decodestring(base64id)
    unencrypted = pyDes.triple_des(short_token()).decrypt(dec, padmode=pyDes.PAD_PKCS5)
    inflated = json.loads(unencrypted)
    return inflated


def logview(event, context):
    print json.dumps(event) # not logger.info() so it doesn't show up in logview itself :)

    qsp = event.get('queryStringParameters')
    if not qsp:
        return {"body": 'Missing logset id (qsp)', "statusCode": 404, "headers": {"Content-Type": "text/html"}}

    lsid = qsp.get('logsetid', False)
    if not lsid:
        return {"body": 'Missing logset id (missing)', "statusCode": 404, "headers": {"Content-Type": "text/html"}}

    group, stream, rid = decode_log_location(lsid)
    filterpattern = '"{}"'.format(rid)

    logger.info("Fetching log for {} : {} : {} (Pattern: {})".format(group, stream, rid, filterpattern))

    # todo: try/catch for no longer existant logs
    client = boto3.client('logs')
    r = client.filter_log_events(
        logGroupName=group,
        logStreamNames=[stream],
        filterPattern=filterpattern
    )
    out = '<html>' \
          '<head>' \
          '<meta name="referrer" content="always">' \
          '<title>Log</title>' \
          '<link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css"' \
          ' rel="stylesheet" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u"' \
          ' crossorigin="anonymous">' \
          '</head>' \
          '<body>' \
          '<table class="table table-striped table-hover table-condensed">' \
          '<thead class="thead-inverse"><tr><th>Timstamp</th><th>Message</th></tr></thead>' \
          '<tbody>'
    for event in r.get('events', []):
        out += "<tr><td nowrap><a href='#{}'>{}</a></td><td>{}</td></tr>".format(
            event.get('eventId'),
            datetime.datetime.utcfromtimestamp(event.get('timestamp') / 1000).strftime('%Y-%m-%d %H:%M:%S'),
            escape_html(event.get('message').strip())
        )
    out += "</tbody></table></body></html>"
    return {"body": out, "statusCode": 200, "headers": {"Content-Type": "text/html"}}


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
    c = Core(source_data=hook_config, schema_files=[os.path.join(os.path.dirname(__file__), "hooks.schema.yml")])
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


def secondary(event, context):
    """
    Evaluate a secondary call
    """
    print json.dumps(event)  # not logger.info() so it doesn't show up in logview itself :)

    logger.info("Processing secondary call...")

    if '_secondary' not in event: # wtf
        return

    es = event['_secondary']
    logger.info("Secondary call is {} with config {}".format(event['_secondary'], json.dumps(event['_hookconfig'])))

    if es == 'hooks_schema':
        hooks_schema(event, context)
    elif es == 'yml_validation':
        yml_validation(event, context)
    elif es == 'approval_count':
        approval_count(event, context)
    elif es == 'always_pass':
        always_pass(event, context)
    else:
        # huh
        logger.error("Unsupported method: ".format(es))

    logger.info("Secondary call for {} complete".format(es))


def always_pass(event, context):
    """
    Add a passing status check to a pr
    """
    fake_done('always_pass', event, context)


def approval_count(event, context):
    """
    Add a pass if the # of approvers is >= config value
    """
    # todo: actually imlement
    fake_done('approval_count', event, context)


def yml_validation(event, context):
    """
    Scan all specified paths and confirm that the yml files are loadably safe
    """
    # todo: actually imlement
    fake_done('yml_validation', event, context)


def hooks_schema(event, context):
    """
    Check if the PR has any changed to .hooks.yml and validate the file
    """
    # todo: actually imlement
    logger.info("Fetching changelist")
    logger.info("Seeing if .hooks.yml present")
    logger.info("Validating branch .hooks.yml")
    fake_done('hooks_schema', event, context)


def fake_done(name, event, context):
    ghevent = json.loads(event['body'])
    repofullname = ghevent['repository']['full_name']
    commitsha = ghevent['pull_request']['head']['sha']
    lsid = encode_log_location(context.log_group_name, context.log_stream_name, context.aws_request_id)
    url = 'https://{}/prod/log?{}'.format(event['headers']['Host'], urllib.urlencode({'logsetid': lsid}))
    logger.info("Sending success to repo {} on sha {} for context {} with url {}".format(
        repofullname,
        commitsha,
        name,
        url
    ))
    get_github()\
        .get_repo(repofullname)\
        .get_commit(commitsha)\
        .create_status('success',
                       description="{} completed".format(name),
                       context=name,
                       target_url=url)


def get_github():
    with open(os.path.join(os.path.dirname(__file__), "ghtoken.txt")) as f:
        ghtoken = f.read().strip()
    return github.Github(ghtoken)


def validate_secret(header_signature, msg):
    with open(os.path.join(os.path.dirname(__file__), "ghsecret.txt")) as f:
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


def escape_html(text):
    """escape strings for display in HTML"""
    import cgi
    return cgi.escape(text, quote=True).\
           replace(u'\n', u'<br />').\
           replace(u'\t', u'&emsp;').\
           replace(u'  ', u' &nbsp;')


# def main():
#     pass # stuff
#
# # For local testing
# if __name__ == "__main__":
#     main()
