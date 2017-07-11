from util.fake_done import fake_done
import check


class AlwaysPass(check.Check):

    configname = 'always_pass'

    def qualify(self, github_event, event_data, hooks_config):

        if self.configname not in hooks_config['hooks']:
            return False

        return hooks_config['hooks'][self.configname]

    def run(self, event, context):
        fake_done(self.configname, event, context)
