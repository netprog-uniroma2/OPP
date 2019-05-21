from operator import attrgetter
from ryu.base import app_manager
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types, in_proto
from ryu.ofproto import ofproto_v1_3
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import csv
import logging
import math
import time
import datetime

LOG = logging.getLogger('app.simple_monitor')
timewindow = 1
precision = 3  # 1 -> small precision 68% / 2 -> medium precision 95% / 3 -> high precision 99,7%


class SimpleMonitor(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.entropy_ipsrc, self.entropy_ipdst, self.entropy_portsrc, self.entropy_portdst, self.abscisse_time = ([] for i in range(5))  # Entropy Lists
        self.datapaths, self.ipsrc, self.ipdst, self.portsrc, self.portdst, self.tcp_portsrc, self.tcp_portdst, self.udp_portsrc, self.udp_portdst = ({} for i in range(9)) # Datapath + Features dictionaries
        # Lists specific for sFlow to drop counters that were detected as possible attacks
        self.victim_address_sflow, self.victim_port_sflow, self.attacker_address_sflow, self.attacker_port_sflow, self.proto_src_sflow, self.proto_dst_sflow = ([] for i in range(6))
        with open('sflow_entropy.csv', 'wb') as csvfile:  # Set the header and Empty the file
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(
                ["Time (s)", " IP Src Entropy", " IP Dst Entropy", " Port Src Entropy", " Port Dst Entropy"])
            csvfile.close()
        with open('sflow_counters.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile, delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(
                ["Time (s)", " IPsrc", " State", " IPdst", " State", " Portsrc", " State", " Portdst", " State"])
            csvfile.close()
        open('sflow_counter_ip_src.csv', 'wb').close()
        open('sflow_counter_ip_dst.csv', 'wb').close()
        open('sflow_counter_port_src.csv', 'wb').close()
        open('sflow_counter_port_dst.csv', 'wb').close()
        self.timer = 1
        self.line_offset = 0
        with open('sflowtraces.csv', 'wb') as csvfile:  # Set the header and Empty the file
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            csvfile.close()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        """ Drop IP-dst Broadcast (for DEMO/EVAL only) """
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="255.255.255.255")
        actions = []
        self.add_flow(datapath, 20, match, actions)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # if src not in self.mac_to_port[dpid]:
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install flow(s) to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                # return
            else:
                self.add_flow(datapath, 10, match, actions)
            if src in self.mac_to_port[dpid]:
                match = parser.OFPMatch(eth_dst=src)
                actions1 = [parser.OFPActionOutput(in_port)]
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 10, match, actions1, msg.buffer_id)
                else:
                    self.add_flow(datapath, 10, match, actions1)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            self.getsFlowvalues()
            if (len(self.udp_portdst) != 0 or len(self.tcp_portdst) != 0):  # If counters are != 0
                self.entropy_computation()
            hub.sleep(timewindow)  # Wait X seconds

    def getsFlowvalues(self):
        with open('sflowtraces.csv', 'rb') as csvfile:
            csvfile.seek(self.line_offset)
            reader = csv.reader(csvfile)
            for row in reader:
                if (len(row) == 5 and len(row[4]) != 0):
                    for i in range(len(row)):
                        self.line_offset += len(row[i])
                    self.line_offset += 5  # add the number of commas + escape char
                    if (len(row[0]) <= 15 and (row[2] == '17' or row[2] == '6' or row[2] == '1') and row[
                        1] != '255.255.255.255'):  # An IPv4, NOT An IPv6, only TCP, UDP and ICMP packets; NOT TO BROADCAST DST
                        Count = True
                        # Do not count features if we have mitigate the attack
                        # Time to retrieve all information about the attack
                        if (len(self.attacker_address_sflow) != 0 and len(self.victim_address_sflow) != 0 and len(
                                self.attacker_port_sflow) != 0 and len(self.victim_port_sflow) != 0):
                            if (len(self.attacker_address_sflow) != 0 and len(self.attacker_port_sflow) != 0 and Count):
                                i = j = 0
                                while i < len(self.attacker_address_sflow):
                                    if (row[0] == self.attacker_address_sflow[i]):
                                        for j in range(len(self.attacker_port_sflow)):
                                            if (row[3] == self.attacker_port_sflow[j] and int(row[2]) ==
                                                self.proto_src_sflow[j]):
                                                i = len(self.attacker_address_sflow)
                                                Count = False
                                                break;
                                    i += 1
                            elif (len(self.attacker_address_sflow) != 0 and len(self.attacker_port_sflow) == 0 and Count):
                                i = j = 0
                                while i < len(self.attacker_address_sflow):
                                    if (row[0] == self.attacker_address_sflow[i]):
                                        i = len(self.attacker_address_sflow)
                                        Count = False
                                        break;
                                    i += 1
                            elif (len(self.victim_address_sflow) != 0 and len(self.victim_port_sflow) != 0 and Count):
                                i = j = 0
                                while i < len(self.victim_address_sflow):
                                    if (row[0] == self.victim_address_sflow[i]):
                                        for j in range(len(self.victim_port_sflow)):
                                            if (row[3] == self.victim_port_sflow[j] and int(row[2]) ==
                                                self.proto_dst_sflow[j]):
                                                i = len(self.victim_address_sflow)
                                                Count = False
                                                break;
                                    i += 1
                            elif (len(self.victim_address_sflow) != 0 and len(self.victim_port_sflow) == 0 and Count):
                                i = j = 0
                                while i < len(self.victim_address_sflow):
                                    if (row[0] == self.victim_address_sflow[i]):
                                        i = len(self.victim_address_sflow)
                                        Count = False
                                        break;
                                    i += 1

                        if (Count):
                            # Counters:
                            # IP_Src
                            if (row[0] in self.ipsrc):
                                new_state = self.ipsrc[row[0]] + 1
                                self.ipsrc[row[0]] = new_state
                            else:
                                self.ipsrc[row[0]] = 1
                            # IP_Dst
                            if (row[1] in self.ipdst):
                                new_state = self.ipdst[row[1]] + 1
                                self.ipdst[row[1]] = new_state
                            else:
                                self.ipdst[row[1]] = 1
                            # Port_Src/Dst
                            # UDP
                            if (row[2] == '17'):
                                # UDP_Port_Src
                                if (row[3] in self.udp_portsrc):
                                    new_state = self.udp_portsrc[row[3]] + 1
                                    self.udp_portsrc[row[3]] = new_state
                                else:
                                    self.udp_portsrc[row[3]] = 1
                                # UDP_Port_Dst
                                if (row[4] in self.udp_portdst):
                                    new_state = self.udp_portdst[row[4]] + 1
                                    self.udp_portdst[row[4]] = new_state
                                else:
                                    self.udp_portdst[row[4]] = 1
                            # TCP
                            elif (row[2] == '6'):
                                # TCP_Port_Src
                                if (row[3] in self.tcp_portsrc):
                                    new_state = self.tcp_portsrc[row[3]] + 1
                                    self.tcp_portsrc[row[3]] = new_state
                                    self.portsrc[row[3]] = new_state
                                else:
                                    self.tcp_portsrc[row[3]] = 1
                                    self.portsrc[row[3]] = 1
                                # TCP_Port_Dst
                                if (row[4] in self.tcp_portdst):
                                    new_state = self.tcp_portdst[row[4]] + 1
                                    self.tcp_portdst[row[4]] = new_state
                                    self.portdst[row[4]] = new_state
                                else:
                                    self.tcp_portdst[row[4]] = 1
                                    self.portdst[row[4]] = 1
            csvfile.close()

    def mean(self, mylist):
        return float(sum(mylist)) / len(mylist) if len(mylist) > 0 else float('nan')

    def variance(self, mylist):
        xmean = self.mean(mylist)
        return self.mean([(x - xmean) ** 2 for x in mylist])

    def entropy(self, dictionary):
        total_states = 0
        entropy = 0
        p = 0

        for index in dictionary:
            total_states += dictionary[index]
        if (total_states != 1 and len(dictionary) != 1):  # Division by 0
            for index in dictionary:
                p = float(dictionary[index]) / total_states
                entropy += (-p * math.log(p, 2)) / (math.log(len(dictionary), 2))  # Normalized entropy
            return round(entropy, 5)
        else:
            return 0

    def detection(self):
        # No threats
        attack_type = mitigation_type = i = 0
        victim_address, victim_port, attacker_address, attacker_port, proto_src, proto_dst = ([] for i in range(6))

        # Entropy IP/Port DST variance calculation for the Statistic Gauss's law limits  
        variance_entropy_ipdst = self.variance(self.entropy_ipdst[:-1])
        variance_entropy_ipsrc = self.variance(self.entropy_ipsrc[:-1])
        variance_entropy_portdst = self.variance(self.entropy_portdst[:-1])

        # DDoS Detection (normal values are in the [meanx-precision*sigma;meanx+precision*sigma] range, if NOT -> Attack!)
        if ((self.mean(self.entropy_ipdst[:-1]) - precision * (variance_entropy_ipdst ** 0.5) > self.entropy_ipdst[-1])
            and (self.mean(self.entropy_portdst[:-1]) - precision * (variance_entropy_portdst ** 0.5) >
                     self.entropy_portdst[-1])):

            LOG.info('\033[91m******* (D)DoS Flooding  DETECTED *******\033[0m')
            LOG.info('\033[91m******* Time: ' + str(datetime.datetime.now().time()) + ' *******\033[0m')
            mitigation_type = 1
            attack_type = 1

        # DoS ICMP FLOODING Detection
        elif (
            (self.mean(self.entropy_ipdst[:-1]) - precision * (variance_entropy_ipdst ** 0.5) > self.entropy_ipdst[-1])
        and (self.mean(self.entropy_ipsrc[:-1]) - precision * (variance_entropy_ipsrc ** 0.5) > self.entropy_ipsrc[
            -1])):

            LOG.info('\033[91m******* DoS ICMP Flooding  DETECTED *******\033[0m')
            LOG.info('\033[91m******* Time: ' + str(datetime.datetime.now().time()) + ' *******\033[0m')
            mitigation_type = 1
            attack_type = 3

        # DDoS ICMP FLOODING Detection
        elif (
            (self.mean(self.entropy_ipdst[:-1]) - precision * (variance_entropy_ipdst ** 0.5) > self.entropy_ipdst[-1])
        and (self.mean(self.entropy_ipsrc[:-1]) + precision * (variance_entropy_ipsrc ** 0.5) < self.entropy_ipsrc[
            -1])):

            LOG.info('\033[91m******* DDoS ICMP Flooding  DETECTED *******\033[0m')
            LOG.info('\033[91m******* Time: ' + str(datetime.datetime.now().time()) + ' *******\033[0m')
            mitigation_type = 1
            attack_type = 4

        # PortScan detection
        elif (
            (self.mean(self.entropy_ipdst[:-1]) - precision * (variance_entropy_ipdst ** 0.5) > self.entropy_ipdst[-1])
        and (self.mean(self.entropy_portdst[:-1]) + precision * (variance_entropy_portdst ** 0.5) <
                 self.entropy_portdst[-1])):

            LOG.info('\033[91m******* PortScan  DETECTED *******\033[0m')
            LOG.info('\033[91m******* Time: ' + str(datetime.datetime.now().time()) + ' *******\033[0m')
            mitigation_type = 1
            attack_type = 2

        # Extract information about the attack
        if (mitigation_type != 0):
            # Victims information:
            # IPs
            variance_IPdst = self.variance((self.ipdst).values())
            for index in self.ipdst:  # Store the IP values greater than the mean+sigma limit
                if (self.mean((self.ipdst).values()) + precision * (variance_IPdst ** 0.5) < self.ipdst[index]):
                    victim_address.append(index)
                    self.victim_address_sflow.append(index)

            # Ports
            if (attack_type == 1):  # if not a portscan attack or ICMP Flooding
                variance_Portdst = self.variance((self.portdst).values())
                for index in self.portdst:
                    if (self.mean((self.portdst).values()) + precision * (variance_Portdst ** 0.5) < self.portdst[
                        index]):
                        victim_port.append(index)
                        self.victim_port_sflow.append(index)
                # Protocols <-> Ports
                for port in victim_port:
                    if port in self.tcp_portdst and port in self.udp_portdst:
                        if (self.tcp_portdst[port] > self.udp_portdst[port]):
                            proto_dst.append(6)
                            self.proto_dst_sflow.append(6)
                        elif (self.tcp_portdst[port] == self.udp_portdst[port]):
                            proto_dst.append(0)
                            self.proto_dst_sflow.append(0)
                        else:
                            proto_dst.append(17)
                            self.proto_dst_sflow.append(17)
                    elif port in self.tcp_portdst:
                        proto_dst.append(6)
                        self.proto_dst_sflow.append(6)
                    elif port in self.udp_portdst:
                        proto_dst.append(17)
                        self.proto_dst_sflow.append(17)

            # Printing the Victims' information:
            for ip in victim_address:
                LOG.info('\033[93m** Victim Host: %s **\033[0m', ip)
            for port in victim_port:
                LOG.info('\033[93m** Victim Portdst: %s **\033[0m', port)

                # Attackers information:
            variance_ipsrc = self.variance((self.ipsrc).values())
            for index in self.ipsrc:  # Store the IP values that are greater than the mean+sigma limit
                if (self.mean((self.ipsrc).values()) + precision * (variance_ipsrc ** 0.5) < self.ipsrc[index]):
                    attacker_address.append(index)
                    self.attacker_address_sflow.append(index)
            if (len(attacker_address) != 0):
                mitigation_type = 2

            # Spoofed Ports Src ? and NOT AN ICMP FLOODING ATTACK
            if (attack_type != 3 and attack_type != 4):
                variance_portsrc = self.variance((self.portsrc).values())
                for index in self.portsrc:  # Store the Port values that are greater than the mean+sigma limit
                    if (self.mean((self.portsrc).values()) + precision * (variance_portsrc ** 0.5) < self.portsrc[
                        index]):
                        attacker_port.append(index)
                        self.attacker_port_sflow.append(index)
                # Protocols <-> Ports
                for port in attacker_port:  # For each port store also the protocol type (needed to send the OF rule)
                    if port in self.tcp_portsrc and port in self.udp_portsrc:
                        if (self.tcp_portsrc[port] > self.udp_portsrc[port]):
                            proto_src.append(6)
                            self.proto_src_sflow.append(6)
                        elif (self.tcp_portsrc[port] == self.udp_portsrc[port]):
                            proto_src.append(0)
                            self.proto_src_sflow.append(0)
                        else:
                            proto_src.append(17)
                            self.proto_src_sflow.append(17)
                    elif port in self.tcp_portsrc:
                        proto_src.append(6)
                        self.proto_src_sflow.append(6)
                    elif port in self.udp_portsrc:
                        proto_src.append(17)
                        self.proto_src_sflow.append(17)

            # Printing the Attackers' information:
            for ip in attacker_address:
                LOG.info('\033[93m** Attacker IP: %s **\033[0m', ip)
            for port in attacker_port:
                LOG.info('\033[93m** Attacker Portsrc: %s **\033[0m', port)

            # Don't store the last entropy values because it was during an abnormal traffic 
            del self.entropy_ipsrc[-1]
            del self.entropy_ipdst[-1]
            if (attack_type != 3 and attack_type != 4):
                del self.entropy_portsrc[-1]
                del self.entropy_portdst[-1]

            # Mitigation process
            # Mitigation only if there is all the information needed:
            if (len(attacker_address) != 0 and len(victim_address) != 0 and len(attacker_port) != 0 and len(
                    victim_port) != 0):
                for dp in self.datapaths.values():
                    # ICMP Mitigation
                    if (attack_type == 3 or attack_type == 4):
                        i = 0
                        if (len(attacker_address) != 0):
                            mitigation_type = 2
                            while (i < len(attacker_address)):
                                self.mitigation(dp, mitigation_type, attacker_address[i], 1, None)
                                i += 1
                        elif (len(victim_address) != 0):
                            while (i < len(victim_address)):
                                self.mitigation(dp, mitigation_type, victim_address[i], 1, None)
                                i += 1
                    else:
                        if (len(attacker_address) != 0):
                            mitigation_type = 2
                            i = j = 0
                            while i < len(attacker_address):
                                if len(attacker_port) != 0:
                                    for j in range(len(attacker_port)):
                                        self.mitigation(dp, mitigation_type, attacker_address[i], proto_src[j],
                                                        attacker_port[j])
                                else:
                                    self.mitigation(dp, mitigation_type, attacker_address[i], None, None)
                                i += 1
                        elif (len(victim_address) != 0):
                            i = j = 0
                            while i < len(victim_address):
                                if len(victim_port) != 0:
                                    for j in range(len(victim_port)):
                                        self.mitigation(dp, mitigation_type, victim_address[i], proto_dst[j],
                                                        victim_port[j])
                                else:
                                    self.mitigation(dp, mitigation_type, victim_address[i], None, None)
                                i += 1

    def mitigation(self, datapath, mitigation_type, ipaddress, protocoltype, port):
        ofparser = datapath.ofproto_parser
        port = int(port)
        if (mitigation_type == 1):  # Mitigation of the Victim's traffic
            if (port != None):
                if (protocoltype == 6):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipaddress,
                                              ip_proto=protocoltype, tcp_dst=port)
                elif (protocoltype == 17):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipaddress,
                                              ip_proto=protocoltype, udp_dst=port)
                elif (protocoltype == 0):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipaddress,
                                              ip_proto=in_proto.IPPROTO_TCP, tcp_dst=port)
                    actions = []
                    self.add_flow(datapath=datapath, table_id=0, priority=100,
                                  match=match, actions=actions)
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipaddress,
                                              ip_proto=in_proto.IPPROTO_UDP, udp_dst=port)
            else:
                if (protocoltype == 1):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipaddress,
                                              ip_proto=protocoltype)
                else:
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ipaddress)

            actions = []
            self.add_flow(datapath=datapath, priority=100,
                          match=match, actions=actions)
            LOG.info('\033[94m** Mitigation (of the Victim) message sent **\033[0m')
        elif (mitigation_type == 2):  # Mitigation of the Attacker's traffic
            if (port != None):
                if (protocoltype == 6):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipaddress,
                                              ip_proto=protocoltype, tcp_src=port)
                elif (protocoltype == 17):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipaddress,
                                              ip_proto=protocoltype, udp_src=port)
                elif (protocoltype == 0):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipaddress,
                                              ip_proto=in_proto.IPPROTO_TCP, tcp_src=port)
                    actions = []
                    self.add_flow(datapath=datapath, table_id=0, priority=100,
                                  match=match, actions=actions)
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipaddress,
                                              ip_proto=in_proto.IPPROTO_UDP, udp_src=port)
            else:
                if (protocoltype == 1):
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipaddress,
                                              ip_proto=protocoltype)
                else:
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipaddress)

            actions = []
            self.add_flow(datapath=datapath, priority=100,
                          match=match, actions=actions)
            LOG.info('\033[94m** Mitigation (of the Attacker) message sent **\033[0m')

    def storeInFile(self):
        # Storing the time
        self.abscisse_time.append(timewindow * self.timer)
        self.timer += 1

        with open('sflow_entropy.csv', 'ab') as csvfile:
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(
                [self.abscisse_time[-1], self.entropy_ipsrc[-1], self.entropy_ipdst[-1], self.entropy_portsrc[-1],
                 self.entropy_portdst[-1]])
            csvfile.close()

        with open('sflow_counters.csv', 'ab') as csvfile:
            writer = csv.writer(csvfile, delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            for index in self.ipsrc:
                writer.writerow([self.abscisse_time[-1], index, self.ipsrc[index], None, None, None, None, None, None])
            for index in self.ipdst:
                writer.writerow([self.abscisse_time[-1], None, None, index, self.ipdst[index], None, None, None, None])
            for index in self.portsrc:
                writer.writerow(
                    [self.abscisse_time[-1], None, None, None, None, index, self.portsrc[index], None, None])
            for index in self.portdst:
                writer.writerow(
                    [self.abscisse_time[-1], None, None, None, None, None, None, index, self.portdst[index]])
            csvfile.close()

        with open('sflow_counter_ip_src.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile, delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["IP Src", " IP Src ID", " State"])
            positionID = 1
            for index in self.ipsrc:
                writer.writerow([index, positionID, self.ipsrc[index]])
                positionID += 1
            csvfile.close()

        with open('sflow_counter_ip_dst.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile, delimiter=';', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["IP Dst", " IP Dst ID", " State"])
            positionID = 1
            for index in self.ipdst:
                writer.writerow([index, positionID, self.ipdst[index]])
                positionID += 1
            csvfile.close()

        with open('sflow_counter_port_src.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["Port Src", " State"])
            for index in self.portsrc:
                writer.writerow([index, self.portsrc[index]])
            csvfile.close()

        with open('sflow_counter_port_dst.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
            writer.writerow(["Port Dst", " State"])
            for index in self.portdst:
                writer.writerow([index, self.portdst[index]])
            csvfile.close()

    def printcounters(self):
        # Print the state stats of the dictionaries
        if ((len(self.ipsrc) != 0) and (len(self.ipdst) != 0) and (len(self.portsrc) != 0) and (
            len(self.portdst) != 0)):
            LOG.info('===========================================')
            for index in self.ipsrc:
                LOG.info('IPsrc= %s \t\tState= %s', index, self.ipsrc[index])
            LOG.info(' ')
            for index in self.ipdst:
                LOG.info('IPdst= %s \t\tState= %s', index, self.ipdst[index])
            LOG.info(' ')
            for index in self.portsrc:
                LOG.info('Portsrc= %s \t\t\tState= %s', index, self.portsrc[index])
            LOG.info(' ')
            for index in self.portdst:
                LOG.info('Portdst= %s \t\t\tState= %s', index, self.portdst[index])

    def entropy_computation(self):
        # Port src dictionary = TCP + UDP Port src dictionaries
        for index in self.udp_portsrc:
            if index in self.portsrc:  # We add the two values
                new_port = self.portsrc[index] + self.udp_portsrc[index]
                self.portsrc[index] = new_port
            else:  # We create a new entry
                self.portsrc[index] = self.udp_portsrc[index]
        # Port dst dictionary = TCP + UDP Port dst dictionaries
        for index in self.udp_portdst:
            if index in self.portdst:
                new_port = self.portdst[index] + self.udp_portdst[index]
                self.portdst[index] = new_port
            else:
                self.portdst[index] = self.udp_portdst[index]

        # self.printcounters()
        LOG.info('===========================================')

        # # Entropy calculation:
        entropy_ip_src = self.entropy(self.ipsrc)
        entropy_ip_dst = self.entropy(self.ipdst)
        entropy_port_src = self.entropy(self.portsrc)
        entropy_port_dst = self.entropy(self.portdst)

        # # Storing entropies in lists:
        self.entropy_ipsrc.append(entropy_ip_src)
        self.entropy_ipdst.append(entropy_ip_dst)
        self.entropy_portsrc.append(entropy_port_src)
        self.entropy_portdst.append(entropy_port_dst)

        LOG.info('Entropy IP Dst')
        LOG.info(self.entropy_ipdst)
        # LOG.info('Entropy Port Src')
        # LOG.info(self.entropy_portsrc)
        LOG.info('Entropy Port Dst')
        LOG.info(self.entropy_portdst)

        # Storing the Counters + Entropies in an output file:
        self.storeInFile()

        # Detection process
        if ((len(self.entropy_ipsrc) > int(20 / timewindow)) and sum(
                self.entropy_ipsrc) > 1):  # Wait 20s before starting the detection, we need at least 2 elements in entropy lists
            self.detection()

        # Emptying dictionaries
        self.ipsrc.clear()
        self.ipdst.clear()
        self.portsrc.clear()
        self.portdst.clear()
        self.tcp_portsrc.clear()
        self.tcp_portdst.clear()
        self.udp_portsrc.clear()
        self.udp_portdst.clear()

    # OF 1.3
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if len(actions) > 0:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority, match=match, instructions=inst)

        datapath.send_msg(mod)
