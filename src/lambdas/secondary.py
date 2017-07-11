import sys,os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vendor"))

import json, logging
from checks import all as all_checks

logger = logging.getLogger(__name__)


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

    # Call the class' run method
    all_checks.get_all_checks()[es].run(event, context)

    logger.info("Secondary call for {} complete".format(es))
