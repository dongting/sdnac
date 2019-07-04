from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
import time

class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."
    def build(self, n=2):
        switch = self.addSwitch('s1')
        for h in range(n):
            host = self.addHost('h%s' % (h + 1))
            self.addLink(host, switch)

def simpleTest():
    "Create and test a simple network"
    topo = SingleSwitchTopo(n=3)
    net = Mininet(topo=topo, controller=lambda name: RemoteController( name, ip='192.168.56.1'))
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    # print "Testing network connectivity"
    net.pingAll()
    
    # start of experiment
    # time.sleep(10)
    h1 = net.get('h1')
    # result = h1.cmd('arp -a')
    # result = h1.cmd('nmap -sU -r -p75-85 10.0.0.3')
    # result = h1.cmd('nmap -sU -r -p1-10 --max-retries 0 10.0.0.3')
    result = h1.cmd('nmap -sU -r -p1-11 --max-retries 0 10.0.0.3')
    print result
    # for i in range(10):
    #     result = h1.cmd('python udp-sender.py')
    # print result
    # end of experiment
    
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    simpleTest()
