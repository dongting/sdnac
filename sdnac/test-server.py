import json
import zmq
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.transports.zmq import ZmqServerTransport
from tinyrpc.server import RPCServer
from tinyrpc.dispatch import RPCDispatcher

ctx = zmq.Context()
dispatcher = RPCDispatcher()
transport = ZmqServerTransport.create(ctx, 'tcp://127.0.0.1:8000')

rpc_server = RPCServer(
    transport,
    JSONRPCProtocol(),
    dispatcher
)

@dispatcher.public
def request(s):
    # return s[::-1]
    rq = json.loads(s)
    print 'REQUEST: '
    print rq['meta']
    print rq['body']
    if 'OFPFlowMod' in rq['body']:
        print rq['body']['OFPFlowMod']
    return 'PERMIT'

rpc_server.serve_forever()