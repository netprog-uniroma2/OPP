import logging
from datetime import date, time, datetime
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4

LOG = logging.getLogger('app.beba.native_monitoring')


class NativeMonitoring(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NativeMonitoring, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.nb_rules = 0
        self.step = 1
        self.t0 = self.t1 = self.timeDiff = datetime.now()
        self.reaction_times = {}  # Dictionary of reaction times: step, reaction time
        self.rep_size = 0
        self.reply_sizes = {}  # Dictionary of reply sizes: step, reply size
        self.output_file = '/home/tai/beba-ctrl/ryu/app/beba/results/results.txt'
        self.monitor_interval = 2
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):
        while (len(self.datapaths.values()) == 0):
            hub.sleep(1)

        f = open(self.output_file, 'wb')
        f.write('# Step | ReactionTime | IpFlowEntriesRep | FlowStatRepSize | TotalFlowEntries | ReqFrequency\n')
        f.close()
        while True:
            for dp in self.datapaths.values():
                LOG.info("Requesting statistics for switch %d (nb rules=%d)", dp.id, self.nb_rules)
                self._request_stats(dp)
            hub.sleep(self.monitor_interval)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        cookie = cookie_mask = 0
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
        req = parser.OFPFlowStatsRequest(datapath, 0,
                                         ofproto.OFPTT_ALL,
                                         ofproto.OFPP_ANY,
                                         ofproto.OFPG_ANY,
                                         cookie, cookie_mask,
                                         match)
        self.t0 = datetime.now()
        # FlowStatsRequest = 130 bytes
        datapath.send_msg(req)

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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Useless with OVS (DHCP requests are not flooded to all switch ports),
        # but added here to make ofsoftswitch (does flood DHCP requests) behave like OVS.
        # """ Drop IP-dst Broadcast (for DEMO/EVAL only) """
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="255.255.255.255")
        actions = []
        self.nb_rules += 1
        self.add_flow(datapath, 0, match=match, actions=actions)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        # Table 0
        self.nb_rules += 1
        self.add_flow(datapath, 0, match, actions)
        # Table 1
        # self.add_flow(datapath, 1, 0, match, actions)

        LOG.debug("Adding switch %d to the list of 'datapaths' (i.e. switches)", datapath.id)
        self.datapaths[datapath.id] = datapath

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        self.t1 = datetime.now()
        self.timeDiff = self.t1 - self.t0
        self.reaction_times[self.step] = self.timeDiff.total_seconds()
        # Eth(14)+IP(20)+TCP(32) headers = 66 bytes
        # FlowStats reply header = 16 bytes
        # 1 full (i.e. match + action) flow entry = 112 bytes
        # 1 flow entry with match but no action = 72 bytes
        if len(ev.msg.body) >= 1:
            self.rep_size = (len(ev.msg.body) - 1) * 112 + 72 + 82
        else:
            self.rep_size = 82  # empty FlowStats reply
        self.reply_sizes[self.step] = self.rep_size
        flows = []
        LOG.info("Parsing flow stat reply (%s bytes)...", self.rep_size)
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                         'duration_sec=%d duration_nsec=%d '
                         'priority=%d '
                         'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                         'cookie=%d packet_count=%d byte_count=%d '
                         'match=%s instructions=%s' %
                         (stat.table_id,
                          stat.duration_sec, stat.duration_nsec,
                          stat.priority,
                          stat.idle_timeout, stat.hard_timeout, stat.flags,
                          stat.cookie, stat.packet_count, stat.byte_count,
                          stat.match, stat.instructions))
        # LOG.info('FlowStats: %s', flows)
        LOG.info('Got %d flow entries in %s', len(flows), self.timeDiff.total_seconds())
        LOG.info('ReactionTimes: %s', self.reaction_times)
        # Step | ReactionTime | IpFlowEntriesRep | FlowStatRepSize | TotalFlowEntries | ReqFrequency
        # LOG.info('%s %s %s %s %s %s', self.step, self.timeDiff.total_seconds(), len(flows), self.rep_size, self.nb_rules, self.monitor_interval)
        result = str(self.step) + ' ' + str(self.timeDiff.total_seconds()) + ' ' + str(len(flows)) + ' ' + str(
            self.rep_size) + ' ' + str(self.nb_rules) + ' ' + str(self.monitor_interval)
        f = open(self.output_file, 'ab')
        f.write(result + '\n')
        f.close()
        self.step += 1

    # MAC learning + IP forwarding
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            LOG.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)

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

        # LOG.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install flow(s) to avoid packet_in next time
        # ARP handling
        if (out_port != ofproto.OFPP_FLOOD and eth.ethertype == ether_types.ETH_TYPE_ARP):
            # match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            match = parser.OFPMatch(eth_dst=dst, eth_type=ether_types.ETH_TYPE_ARP)
            self.nb_rules += 1
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # IP forwarding
        elif (out_port != ofproto.OFPP_FLOOD and eth.ethertype == ether_types.ETH_TYPE_IP):
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            ipsrc = ip.src
            ipdst = ip.dst
            # LOG.info("Install IP forwarding rule: IP src %s ==> IP dst: %s", ipsrc, ipdst)

            match = parser.OFPMatch(eth_dst=dst, eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ipsrc, ipv4_dst=ipdst)
            self.nb_rules += 1

            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
