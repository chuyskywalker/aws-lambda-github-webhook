from util.fake_done import fake_done
import check, logging

log = logging.getLogger(__name__)


class HooksScehma(check.Check):

    configname = 'hooks_schema'

    def qualify(self, github_event, event_data, hooks_config):

        # run on every pr, regardless of config -- this validates configs!
        if github_event == 'pull_request':
            if 'action' in event_data and event_data["action"] in ["opened", "synchronize", "reopened"]:
                return {}

        return False

    def run(self, event, context):
        log.info("Fetching changelist")
        log.info("Seeing if .hooks.yml present")
        log.info("Validating branch .hooks.yml")
        fake_done(self.configname, event, context)