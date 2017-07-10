import sys,os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vendor"))

import github


def get_github():
    with open(os.path.join(os.path.dirname(__file__), "..", "ghtoken.txt")) as f:
        ghtoken = f.read().strip()
    return github.Github(ghtoken)