import sys,os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vendor"))

import json, logging
from checks.yml_validation import yml_validation
from checks.hooks_schema import hooks_schema
from checks.approval_count import approval_count
from checks.always_pass import always_pass

logger = logging.getLogger()


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
