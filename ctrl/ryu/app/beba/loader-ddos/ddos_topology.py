from mininet.net import Mininet
from mininet.node import UserSwitch,RemoteController, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class CustomHost(Host):
    def config(self, **params):
        r = super(Host, self).config(**params)

        self.defaultIntf().rename("eth0")

        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            self.cmd(cmd)

        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return r


def ddos():
    net = Mininet(controller=RemoteController, switch=UserSwitch, autoStaticArp=True, host=CustomHost)

    info('*** Adding controller\n')
    net.addController('c0')

    topo_scheme = """
                          s1
                          |
            3   1         |3        1   3
    h1 ----- sw1 ------- sw2 ------- sw3 ----- h3
              | 2       1   2       2 |
            3 | 2                   1 | 3
      s4 --- sw8                     sw4 --- s3
              | 1                   2 |
            2 |         2   1       1 | 3
    h2 ----- sw7 ------- sw6 ------- sw5 ----- h4
            3   1         |3        2   
                          |
                          s2\n"""

    # servers
    net.addHost('s1', mac="00:00:00:00:00:01", ip="10.0.0.1/24")
    net.addHost('s2', mac="00:00:00:00:00:02", ip="10.0.0.2/24")
    net.addHost('s3', mac="00:00:00:00:00:03", ip="10.0.0.3/24")
    net.addHost('s4', mac="00:00:00:00:00:04", ip="10.0.0.4/24")

    # autonomous systems
    net.addHost('h1', mac="00:00:00:00:00:10", ip="10.0.0.10/24")
    net.addHost('h2', mac="00:00:00:00:00:20", ip="10.0.0.20/24")
    net.addHost('h3', mac="00:00:00:00:00:30", ip="10.0.0.30/24")
    net.addHost('h4', mac="00:00:00:00:00:40", ip="10.0.0.40/24")

    # add switches
    net.addSwitch('sw1')
    net.addSwitch('sw2')
    net.addSwitch('sw3')
    net.addSwitch('sw4')
    net.addSwitch('sw5')
    net.addSwitch('sw6')
    net.addSwitch('sw7')
    net.addSwitch('sw8')

    info('*** Creating links\n')
    info(topo_scheme)

    # ring links
    net.addLink('sw1', 'sw2')
    net.addLink('sw2', 'sw3')
    net.addLink('sw3', 'sw4')
    net.addLink('sw4', 'sw5')
    net.addLink('sw5', 'sw6')
    net.addLink('sw6', 'sw7')
    net.addLink('sw7', 'sw8')
    net.addLink('sw8', 'sw1')

    # autonomous systems -> edge switches links 
    net.addLink('h1', 'sw1')
    net.addLink('h3', 'sw3')
    net.addLink('h4', 'sw5')
    net.addLink('h2', 'sw7')

    # servers to core switches
    net.addLink('s1', 'sw2')
    net.addLink('s2', 'sw4')
    net.addLink('s3', 'sw6')
    net.addLink('s4', 'sw8')

    net.start()

    # info('*** Starting tcpdump captures on ring links\n')
    # start_capture(net)

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network')
    net.stop()


def start_capture(net):
    # ring links captures
    net.get('sw1').cmd("tcpdump -ni sw1-eth1 -w ~/distributed-ddos/cap/sw1-2.pcap 2>/dev/null &")
    net.get('sw2').cmd("tcpdump -ni sw2-eth2 -w ~/distributed-ddos/cap/sw2-3.pcap 2>/dev/null &")
    net.get('sw3').cmd("tcpdump -ni sw3-eth2 -w ~/distributed-ddos/cap/sw3-4.pcap 2>/dev/null &")
    net.get('sw4').cmd("tcpdump -ni sw4-eth2 -w ~/distributed-ddos/cap/sw4-5.pcap 2>/dev/null &")
    net.get('sw5').cmd("tcpdump -ni sw5-eth2 -w ~/distributed-ddos/cap/sw5-6.pcap 2>/dev/null &")
    net.get('sw6').cmd("tcpdump -ni sw6-eth2 -w ~/distributed-ddos/cap/sw6-7.pcap 2>/dev/null &")
    net.get('sw7').cmd("tcpdump -ni sw7-eth2 -w ~/distributed-ddos/cap/sw7-8.pcap 2>/dev/null &")
    net.get('sw8').cmd("tcpdump -ni sw8-eth2 -w ~/distributed-ddos/cap/sw8-1.pcap 2>/dev/null &")
    net.get('s1').cmd("tcpdump -ni eth0 -w ~/distributed-ddos/cap/s1.pcap 2>/dev/null &")
    net.get('s2').cmd("tcpdump -ni eth0 -w ~/distributed-ddos/cap/s2.pcap 2>/dev/null &")
    net.get('s3').cmd("tcpdump -ni eth0 -w ~/distributed-ddos/cap/s3.pcap 2>/dev/null &")
    net.get('s4').cmd("tcpdump -ni eth0 -w ~/distributed-ddos/cap/s4.pcap 2>/dev/null &")


if __name__ == '__main__':
    setLogLevel('info')
    ddos()
