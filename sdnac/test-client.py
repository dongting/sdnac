# simple client
import json
import zmq
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.transports.zmq import ZmqClientTransport
from tinyrpc import RPCClient

ctx = zmq.Context()

rpc_client = RPCClient(
    JSONRPCProtocol(),
    ZmqClientTransport.create(ctx, 'tcp://127.0.0.1:8000')
)

remote_server = rpc_client.get_proxy()

data = {'app':'firewall','query':'evaluate','body':''}
data['body'] = {'of_action':'OFPT_HELLO', 'subject':['app','firewall'], 'resource':['switch']}
print remote_server.request(json.dumps(data))

