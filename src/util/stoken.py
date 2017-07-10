import sys,os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vendor"))

import json, pyDes, base64

"""
Listen, alright, I know this isn't the most perfectly, cryptographically secure 
setup in the world. That said, it's portable and "good enough" to hide a few params.
"""


def short_token():
    with open(os.path.join(os.path.dirname(__file__), "..", "ghtoken.txt")) as f:
        ghtoken = f.read().strip()[0:24]
    return ghtoken


def encode_log_location(group, stream, reqid):
    val = json.dumps([group, stream, reqid])
    enc = pyDes.triple_des(short_token()).encrypt(val, padmode=pyDes.PAD_PKCS5)
    return base64.encodestring(enc)


def decode_log_location(base64id):
    dec = base64.decodestring(base64id)
    unencrypted = pyDes.triple_des(short_token()).decrypt(dec, padmode=pyDes.PAD_PKCS5)
    inflated = json.loads(unencrypted)
    return inflated
