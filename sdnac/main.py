import sys
import time
import ujson as json
import base64

import api
import ofproto
import policy
import services

META_KEY = 'meta'
QUERY_KEY = 'query'
# QUERIES = ['evaluate', 'delegate', 'issue']
QUERIES = ['evaluate']
PERMIT = 'permit'
DENY = 'deny'
UNKNOWN = 'unknown'
REPLIES = [PERMIT, DENY, UNKNOWN]
DECISION_KEY = 'decision'
CAP_KEY = 'capability'

pobj = None

def request(req):
    # print 'REQUEST: '
    # print req
    robj = json.loads(req)
    query_type = robj[META_KEY][QUERY_KEY]
    if query_type in QUERIES:
        sta = time.clock()
        decision, cap = getattr(services, query_type)(robj, policy=pobj)
        end = time.clock()
        print end-sta, '\n'
        if decision in REPLIES:
            return reply(decision, cap)
    return reply(UNKNOWN, cap)

def reply(decision, cap):
    # print 'DECISION: '
    # print decision
    # print '-------------------'
    resp = json.dumps({DECISION_KEY:decision, CAP_KEY:cap})
    return resp

def main():
    global pobj
    # initialise/parse policy file
    policy_file = sys.argv[1]
    pobj = policy.PolicyEngine(policy_file)
    
    # initialise API server
    api.Server(request)

if __name__ == '__main__':
    # print 'STARTc: '+str(time.clock())
    if len(sys.argv) <= 1:
        # TODO: perhaps use a default all-pass policy?
        print 'Usage: python main.py <policy_file>'
        sys.exit()
    main()
