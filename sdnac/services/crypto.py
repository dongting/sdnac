from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
import base64
import ujson as json

PRIV_KEY_FILE = 'priv_key.pem'
PUB_KEY_FILE = 'pub_key.pem'

RULE_KEY = 'rule'
EXPIRE_KEY = 'expire'
SIG_KEY = 'sig'
CAP_KEY = 'capability'

def load_key(fname):
    f = open(fname, 'r')
    key = RSA.importKey(f.read())
    f.close()
    return key

pr_key = load_key(PRIV_KEY_FILE)
signer = PKCS1_PSS.new(pr_key)

pub_key = load_key(PUB_KEY_FILE)
verifier = PKCS1_PSS.new(pub_key)

def sign_cap(cap_body):
    h = SHA256.new(cap_body)
    sig = signer.sign(h)
    return json.dumps({CAP_KEY:cap_body, SIG_KEY:base64.b64encode(sig)})

def check_cap(req, cap):
    cap_json = json.loads(base64.b64decode(cap))
    cap_body = cap_json[CAP_KEY]
    cap_sig = cap_json[SIG_KEY]
    
    h = SHA256.new(cap_body)
    if verifier.verify(h, base64.b64decode(cap_sig)):
        return cap_body
    else:
        # return cap_body
        return None
    return None


