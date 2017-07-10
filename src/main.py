import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# lambda hook for logview:
from lambdas.logview import logview

# lambda hook for incoming:
from lambdas.incoming import incoming

# lambda hook for secondary:
from lambdas.secondary import secondary

# def main():
#     pass # stuff
#
# # For local testing
# if __name__ == "__main__":
#     main()
