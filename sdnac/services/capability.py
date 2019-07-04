import ujson as json
import time
import base64

import crypto

RULE_KEY = 'rule'
EXPIRE_KEY = 'expire'
SIG_KEY = 'sig'
CAP_KEY = 'capability'
ONE_HOUR = 3600

def issue(rule):
    '''
    issue a signed capability object
    '''
    curr_time = int(time.time())
    expire_time = curr_time + ONE_HOUR
    cap_body = dict()
    cap_body[RULE_KEY] = rule
    cap_body[EXPIRE_KEY] = expire_time
    cap_json = json.dumps(cap_body)
    cap = base64.b64encode(crypto.sign_cap(cap_json))
    return cap

def delegate():
    pass
