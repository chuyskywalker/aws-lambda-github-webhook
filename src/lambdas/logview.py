import sys,os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vendor"))

import json, boto3, datetime, logging
from util.stoken import decode_log_location

logger = logging.getLogger(__name__)


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


def escape_html(text):
    """escape strings for display in HTML"""
    import cgi
    return cgi.escape(text, quote=True).\
           replace(u'\n', u'<br />').\
           replace(u'\t', u'&emsp;').\
           replace(u'  ', u' &nbsp;')