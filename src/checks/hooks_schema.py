import sys,os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vendor"))

import check, logging, json, github, yaml
from util.fake_done import send_status
from util.tfgithub import get_github
from pykwalify.core import Core

logger = logging.getLogger(__name__)


class HooksScehma(check.Check):

    configname = 'hooks_schema'

    def qualify(self, github_event, event_data, hooks_config):

        # run on every pr, regardless of config -- this validates configs!
        if github_event == 'pull_request':
            if 'action' in event_data and event_data["action"] in ["opened", "synchronize", "reopened"]:
                return {}

        return False

    def run(self, event, context):

        gh_hook = json.loads(event['body'])

        logger.info("Fetching .hook.yml from branch")

        repo = gh_hook['repository']['full_name']
        sha = gh_hook['pull_request']['head']['sha']

        try:
            hooks_yml = get_github().get_repo(repo, lazy=True).get_file_contents('.hooks.yml', ref=sha)
            logger.info("Fetched .hooks.yml from repo {}".format(repo))
        except github.GithubException:
            logger.error("Missig .hooks.yml on repo {}".format(repo))
            send_status(event, context, gh_hook, self.configname, 'success', ".hooks.yml not present in branch")
            return

        try:
            hook_config = yaml.safe_load(hooks_yml.decoded_content)
            logger.info("Basic yml validation passed")
        except Exception as e:
            logger.error("Failed to decode hook yaml: " + e.message)
            send_status(event, context, gh_hook, self.configname, 'failure', "Could not decode branch .hooks.yml")
            return

        logger.info("Advanced schema validation")
        c = Core(source_data=hook_config,
                 schema_files=[os.path.join(os.path.dirname(__file__), "..", "hooks.schema.yml")])
        c.validate(raise_exception=False)
        if len(c.validation_errors) > 0:
            logger.error(c.validation_errors)
            send_status(event, context, gh_hook, self.configname, 'failure', ".hooks.yml has validation errors; see log")
            return

        send_status(event, context, gh_hook, self.configname, 'success', ".hooks.yml present and valid")
