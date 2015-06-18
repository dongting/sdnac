import sys
import json
#from api import api
from api import rpc as api
from policy import policy
import ofproto

def request_callback(req):
    data = json.loads(req)
    print data['app'], data['body']

def main():
    # initialise/parse policy file
    policy_file = sys.argv[1]
    policy.PolicyEngine(policy_file)
    
    # initialise API server
    #api.ApiServer(request_callback)
    api.Server(request_callback)

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print 'Usage: python main.py <policy_file>'
        sys.exit()
    main()
