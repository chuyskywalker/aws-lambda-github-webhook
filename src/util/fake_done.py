import json, logging, urllib
from util.stoken import encode_log_location
from util.tfgithub import get_github

logger = logging.getLogger(__name__)


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