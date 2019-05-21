from mininet.net import Mininet
from mininet.node import UserSwitch, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def myNet():
    net = Mininet(controller=RemoteController, switch=UserSwitch, link=TCLink, autoStaticArp=True)

    info('*** Adding controller\n')
    net.addController('c0')

    net.addHost('h1', mac="00:00:00:00:00:01")
    net.addHost('h2', mac="00:00:00:00:00:02")
    net.addHost('h3', mac="00:00:00:00:00:03")
    # leaves
    net.addSwitch('s1')
    net.addSwitch('s2')
    net.addSwitch('s3')
    # spines
    net.addSwitch('s4')
    net.addSwitch('s5')

    info('*** Creating links\n')
    net.addLink('s1', 's4', bw=5,  delay="5ms")
    net.addLink('s1', 's5', bw=5,  delay="5ms")
    net.addLink('s2', 's4', bw=5,  delay="5ms")
    net.addLink('s2', 's5', bw=5,  delay="5ms")
    net.addLink('s3', 's4', bw=5,  delay="5ms")
    net.addLink('s3', 's5', bw=5,  delay="5ms")
    net.addLink('h1', 's1', bw=10, delay="5ms")
    net.addLink('h2', 's2', bw=10, delay="5ms")
    net.addLink('h3', 's3', bw=10, delay="5ms")

    info('*** Starting network\n')
    net.start()

    info('*** Disabling tcp-segmentation overload on hosts\' interfaces\n')
    info('    ofsoftswitch13 supports segments of length <= 1514 only\n')
    net.get('h1').cmd("ethtool -K h1-eth0 tso off")
    net.get('h2').cmd("ethtool -K h2-eth0 tso off")
    net.get('h3').cmd("ethtool -K h3-eth0 tso off")

    info( '*** Starting tcpdump on node\'s interfaces\n')
    net.get('h1').cmd("tcpdump -ni h1-eth0 -w ~/h1-eth0.pcap > /dev/null 2>&1 &")
    net.get('h2').cmd("tcpdump -ni h2-eth0 -w ~/h2-eth0.pcap > /dev/null 2>&1 &")
    net.get('s1').cmd("tcpdump -ni s1-eth1 -w ~/s1-eth1.pcap > /dev/null 2>&1 &")
    net.get('s1').cmd("tcpdump -ni s1-eth2 -w ~/s1-eth2.pcap > /dev/null 2>&1 &")
    net.get('s2').cmd("tcpdump -ni s2-eth1 -w ~/s2-eth1.pcap > /dev/null 2>&1 &")
    net.get('s2').cmd("tcpdump -ni s2-eth2 -w ~/s2-eth2.pcap > /dev/null 2>&1 &")

    info('\n*** Opening iperf3 servers on hosts (10.0.0.1-3), on ports 6666-6667-6668]\n')

    net.get('h1').cmd("iperf3 -s --daemon -p 6666 > /dev/null 2>&1 &")
    net.get('h1').cmd("iperf3 -s --daemon -p 6667 > /dev/null 2>&1 &")
    net.get('h2').cmd("iperf3 -s --daemon -p 6666 > /dev/null 2>&1 &")
    net.get('h2').cmd("iperf3 -s --daemon -p 6667 > /dev/null 2>&1 &")
    net.get('h3').cmd("iperf3 -s --daemon -p 6666 > /dev/null 2>&1 &")
    net.get('h3').cmd("iperf3 -s --daemon -p 6667 > /dev/null 2>&1 &")

    # using low bitrate flows to refresh the estimates, for testing purposes.
    # iperf3 required, comment the next lines if it is not installed.

    net.get('h1').cmd("iperf3 -s --daemon -p 10000 > /dev/null 2>&1 &")
    net.get('h1').cmd("iperf3 -s --daemon -p 10001 > /dev/null 2>&1 &")
    net.get('h2').cmd("iperf3 -s --daemon -p 10000 > /dev/null 2>&1 &")
    net.get('h2').cmd("iperf3 -s --daemon -p 10001 > /dev/null 2>&1 &")
    net.get('h3').cmd("iperf3 -s --daemon -p 10000 > /dev/null 2>&1 &")
    net.get('h3').cmd("iperf3 -s --daemon -p 10001 > /dev/null 2>&1 &")

    net.get('h1').cmd("iperf3 -c 10.0.0.2 -p 10000 -l 1 -b 1b -t 1000 > /dev/null 2>&1 &")
    net.get('h1').cmd("iperf3 -c 10.0.0.2 -p 10001 -l 1 -b 1b -t 1000 > /dev/null 2>&1 &")
    net.get('h2').cmd("iperf3 -c 10.0.0.3 -p 10000 -l 1 -b 1b -t 1000 > /dev/null 2>&1 &")
    net.get('h2').cmd("iperf3 -c 10.0.0.3 -p 10001 -l 1 -b 1b -t 1000 > /dev/null 2>&1 &")
    net.get('h3').cmd("iperf3 -c 10.0.0.1 -p 10000 -l 1 -b 1b -t 1000 > /dev/null 2>&1 &")
    net.get('h3').cmd("iperf3 -c 10.0.0.1 -p 10001 -l 1 -b 1b -t 1000 > /dev/null 2>&1 &")

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    myNet()
