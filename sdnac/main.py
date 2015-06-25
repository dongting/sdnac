import sys
import json
import api
import ofproto
import policy
import services

QUERY_KEY = 'query'
QUERIES = ['evaluate', 'delegate', 'issue']
PERMIT = 'permit'
DENY = 'deny'
UNKNOWN = 'unknown'
REPLIES = [PERMIT, DENY, UNKNOWN]

pobj = None

def request_callback(req):
    print 'REQUEST: '
    print req
    robj = json.loads(req)
    if robj[QUERY_KEY] in QUERIES:
        decision = getattr(services, robj[QUERY_KEY])(robj, policy=pobj)
        if decision in REPLIES:
            return reply(decision)
    return reply(UNKNOWN)

def reply(decision):
    print 'DECISION: '
    print decision

def main():
    global pobj
    # initialise/parse policy file
    policy_file = sys.argv[1]
    pobj = policy.PolicyEngine(policy_file)
    
    # initialise API server
    api.Server(request_callback)

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        # TODO: perhaps use a default all-pass policy?
        print 'Usage: python main.py <policy_file>'
        sys.exit()
    main()
