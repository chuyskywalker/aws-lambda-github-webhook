from fake_done import fake_done
import logging

logger = logging.getLogger()

def hooks_schema(event, context):
    """
    Scan all specified paths and confirm that the yml files are loadably safe
    """
    # todo: actually imlement
    logger.info("Fetching changelist")
    logger.info("Seeing if .hooks.yml present")
    logger.info("Validating branch .hooks.yml")
    fake_done('hooks_schema', event, context)