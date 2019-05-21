import logging
from ryu.base import app_manager
from ryu.lib.packet import ether_types, in_proto
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

LOG = logging.getLogger('app.beba.selective_monitoring_1')

# Number of switch ports
N = 3
LOG.info("Support max %d ports per switch" % N)
features = {0: [ofproto.OXM_OF_IPV4_SRC],
            1: [ofproto.OXM_OF_IPV4_DST],
            2: [ofproto.OXM_OF_TCP_SRC],
            3: [ofproto.OXM_OF_TCP_DST],
            4: [ofproto.OXM_OF_UDP_SRC],
            5: [ofproto.OXM_OF_UDP_DST]};
LOG.info("%d Features monitored: IP SRC/DST, TCP/UDP PORTS SRC/DST", len(features))


class BebaSelectiveMonitoring_1(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(BebaSelectiveMonitoring_1, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        LOG.info("Configuring switch %d..." % datapath.id)

        """ Configuration of the State Tables """
        for table in range(len(features) + 1):  # Add 1 for the Mac learning table

            """ Set tables as stateful """
            req = bebaparser.OFPExpMsgConfigureStatefulTable(datapath=datapath,
                                                             table_id=table,
                                                             stateful=1)
            datapath.send_msg(req)

            if table != 6:
                """ Set lookup extractor """
                req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                                     command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                                     fields=features[table],
                                                     table_id=table)
                datapath.send_msg(req)

                """ Set update extractor """
                req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                                     command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                                     fields=features[table],
                                                     table_id=table)
                datapath.send_msg(req)

                if table == 0:
                    """ Increment State + forward to the TCP / UDP Table """
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table + 1)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=10, match=match, instructions=inst)
                    datapath.send_msg(mod)

                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table + 1)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=10, match=match, instructions=inst)
                    datapath.send_msg(mod)

                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_ICMP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table + 1)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=10, match=match, instructions=inst)
                    datapath.send_msg(mod)

                elif table == 1:
                    """ Increment State + forward to the TCP / UDP Table """
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table + 1)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=10, match=match, instructions=inst)
                    datapath.send_msg(mod)

                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table + 3)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=10, match=match, instructions=inst)
                    datapath.send_msg(mod)

                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_ICMP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table + 5)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=10, match=match, instructions=inst)
                    datapath.send_msg(mod)

                elif table == 3:
                    """ Increment State + forward to the last Table """
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table + 3)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=0, match=match, instructions=inst)
                    datapath.send_msg(mod)
                
                else:
                    """ Increment State + forward to the next Table """
                    match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
                    actions = [bebaparser.OFPExpActionIncState(table_id=table)]
                    inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(table_id=table + 1)]
                    mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table,
                                              priority=0, match=match, instructions=inst)
                    datapath.send_msg(mod)
            
            else:
                #########################################################################
                #						MAC LEARNING IMPLEMENTATION						#
                #########################################################################
                """ Set table 6 as stateful """
                req = bebaparser.OFPExpMsgConfigureStatefulTable(
                    datapath=datapath,
                    table_id=table,
                    stateful=1)
                datapath.send_msg(req)

                """ Set lookup extractor = {eth_dst} """
                req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                                     command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                                     fields=[ofproto.OXM_OF_ETH_DST],
                                                     table_id=table)
                datapath.send_msg(req)

                """ Set update extractor = {eth_src}  """
                req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                                     command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                                     fields=[ofproto.OXM_OF_ETH_SRC],
                                                     table_id=table)
                datapath.send_msg(req)
                # for each input port, for each state
                for i in range(1, N + 1):
                    for s in range(N + 1):
                        match = ofparser.OFPMatch(in_port=i, state=s)
                        if s == 0:
                            out_port = ofproto.OFPP_FLOOD
                        else:
                            out_port = s
                        actions = [bebaparser.OFPExpActionSetState(state=i, table_id=table, hard_timeout=10),
                                   ofparser.OFPActionOutput(out_port)]
                        self.add_flow(datapath=datapath, table_id=table, priority=0,
                                      match=match, actions=actions)
                #########################################################################

        """ Table 0 """
        """ ARP packets forwarding """
        match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        inst = [ofparser.OFPInstructionGotoTable(table_id=table)]
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
                                  priority=20, match=match, instructions=inst)
        datapath.send_msg(mod)

        """ Drop IP-dst Broadcast for DEMO only """
        match = ofparser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst="255.255.255.255")
        actions = []
        self.add_flow(datapath=datapath, table_id=0, priority=20,
                      match=match, actions=actions)

    def add_flow(self, datapath, table_id, priority, match, actions):
        if len(actions) > 0:
            inst = [ofparser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                  priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
