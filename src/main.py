import logging

# locally works, but I think lambda overrides this by running one sooner
logging.basicConfig()

# Set the root to ERROR level
logging.getLogger().setLevel(logging.ERROR)

# INFO our loggers
logging.getLogger('checks').setLevel(logging.INFO)
logging.getLogger('lambdas').setLevel(logging.INFO)
logging.getLogger('util').setLevel(logging.INFO)

# FINE
logging.getLogger('pykwalify').setLevel(logging.CRITICAL)

# lambda hook for logview:
from lambdas.logview import logview

# lambda hook for incoming:
from lambdas.incoming import incoming

# lambda hook for secondary:
from lambdas.secondary import secondary


def main():
    pass # stuff

# For local testing
if __name__ == "__main__":
    main()
