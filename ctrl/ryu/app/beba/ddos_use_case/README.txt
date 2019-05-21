
DDoS Use Case :
---------------

[File Descriptions]
###################

-   native_monitoring.py (in ddos_use_case/) implements:
        
	MAC learning and ARP forwarding
        IP forwarding: rules inserted for each couple IP src/dst
        monitoring: every <timeInterval>, a FlowStatsReq is sent to the switch for collecting flows' counters

-   selective_monitoring_1.py (in ddos_use_case/) implements:
    
        Switch flow tables configuration for MAC learning/ARP forwarding
        Counters for four features: -IP Src/Dst and Port Src/Dst

-   simple_monitoring_1.py (in ddos_use_case/) implements:
        
	Inherit from selectivemonitoring
        Sends requests and receives replies from the switch to get counter values of the features monitored
        Every N seconds (Timewindow) process these counter values into an DDoS entropy-based algorithm in order to detect specific attacks
        If an attack is detected sends flow rules to the switch for the attack mitigation

-   simple_monitor.py (in /beba-ctrl/ryu/app/) implements:

        Switch flow tables configuration for MAC learning/ARP forwarding
        Combined with an sFlow Agent and Collector
        Receives samples send by the Agent to the Collector, and parse them to retrieve counters information for the -IP Src/Dst and Port Src/Dst
        Every N seconds (Timewindow) process these counter values into an DDoS entropy-based algorithm in order to detect specific attacks
        If an attack is detected sends flow rules to the switch for the attack mitigation

-   selective_monitoring.py (in ddos_use_case/) (same as selectivemonitoring_1.py but for only one feature)

-   simple_monitoring.py (in ddos_use_case/) (same as seimplemonitoring_1.py but for only one feature)


[Tutorial] 
##########

1/ Open 2 different terminals (one for the switch and one for the controller)
--

2/ (controller-side)
--
cd /beba-ctrl/ryu/app/beba/ddos_use_case
sudo ryu-manager simple_monitoring_1.py

3/ (switch-side)
--
cd /beba-ctrl/ryu/app/beba/ddos_use_case
sudo mn --topo single,3 --mac --switch user --controller remote
xterm h1 h2 h3

h3: python echo_server_udp.py 69
h1: tcpreplay --intf1=h1-eth0 --loop=0 --multiplier=0.3 --quiet Databases/bigFlows_50000.pcap

4/ After at least 20 seconds, launch the UDP flooding attack:
h2: hping3 --udp -s 40 -k -p 69 -i u1 10.0.0.3


[Commands] 
##########

Watch the static flow entries:
------------------------------
xterm s1
sudo dpctl -c unix:/tmp/s1 stats-flow

Watch the flow entries updated:
-------------------------------
xterm s1
sudo dpctl -c unix:/tmp/s1 stats-state
