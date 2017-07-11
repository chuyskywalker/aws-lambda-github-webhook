from util.fake_done import fake_done
import check


class ApprovalCount(check.Check):

    configname = 'approval_count'

    def qualify(self, github_event, event_data, hooks_config):

        if self.configname not in hooks_config['hooks']:
            return False

        config = hooks_config['hooks'][self.configname]

        if github_event == 'pull_request':
            if 'action' in event_data and event_data["action"] in ["opened", "synchronize", "reopened"]:
                return config

        if github_event == 'pull_request_review':
            if 'action' in event_data and event_data["action"] in ["submitted", "edited"]:
                return config

        return False

    def run(self, event, context):
        fake_done(self.configname, event, context)