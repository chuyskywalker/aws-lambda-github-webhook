from abc import ABCMeta, abstractmethod


class Check(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def qualify(self, github_event, event_data, hooks_config):
        """
        Return boolean whether this event should be continued to a "run"
        """
        pass

    @abstractmethod
    def run(self, event, context):
        """
        Process the full run of this check
        """
        pass