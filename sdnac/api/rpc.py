# adapted from zmq_server_example.py in tinyrpc
import time, sys
import zmq
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.transports.zmq import ZmqServerTransport
from tinyrpc.server import RPCServer
from tinyrpc.dispatch import RPCDispatcher

class Server(object):
    def __init__(self, req_callback):
        # print 'initializing Rpc'
        self.ctx = zmq.Context()
        self.dispatcher = RPCDispatcher()
        self.transport = ZmqServerTransport.create(self.ctx, 'tcp://127.0.0.1:8000')
        
        self.req_callback = req_callback
        
        self.rpc_server = RPCServer(
            self.transport,
            JSONRPCProtocol(),
            self.dispatcher
        )
        self.dispatcher.public(self.request)  # register this function (replacing the decorator)
        
        # print 'READYc: '+str(time.clock())
        # sys.exit(0)
        
        self.rpc_server.serve_forever()
    
    # def start(self):
    #     self.rpc_server.serve_forever()
    
    def request(self, req):
        return self.req_callback(req)
    
    
