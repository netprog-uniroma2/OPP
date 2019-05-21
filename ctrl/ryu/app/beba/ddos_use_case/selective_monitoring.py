import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

LOG = logging.getLogger('app.beba.selective_monitoring')

LOG.info("Feature monitored: ipv4_src")

class BebaSelectiveMonitoring(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(BebaSelectiveMonitoring, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):

        msg = event.msg
        datapath = msg.datapath

        LOG.info("Configuring switch %d..." % datapath.id)

        """ Set table as stateful """
        req = bebaparser.OFPExpMsgConfigureStatefulTable(datapath=datapath,
                                                         table_id=0,
                                                         stateful=1)
        datapath.send_msg(req)

        """ Set lookup extractor = {ip_src} """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IPV4_SRC],
                                             table_id=0)
        datapath.send_msg(req)

        """ Set update extractor = {ip_src} (same as lookup) """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IPV4_SRC],
                                             table_id=0)
        datapath.send_msg(req)

        """ Table 0 """
        """ ARP packets flooding """
        match = ofparser.OFPMatch(eth_type=0x0806)
        actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath=datapath, table_id=0, priority=10,
                      match=match, actions=actions)

        """ Drop IP-dst Broadcast """
        match = ofparser.OFPMatch(eth_type=0x0800, ipv4_dst="255.255.255.255")
        actions = []
        self.add_flow(datapath=datapath, table_id=0, priority=10,
                      match=match, actions=actions)

        match = ofparser.OFPMatch(eth_type=0x0800)
        actions = [bebaparser.OFPExpActionIncState(table_id=0)]
        inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
                                  priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_flow(self, datapath, table_id, priority, match, actions):
        if len(actions) > 0:
            inst = [ofparser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                  priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
