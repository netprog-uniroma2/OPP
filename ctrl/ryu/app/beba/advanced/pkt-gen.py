import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser
from ryu.lib import hub
from scapy.contrib.mpls import MPLS
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

LOG = logging.getLogger('app.openstate.evolution')

# Probe packet generated with scapy
pkt = Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00")/MPLS(ttl=64)/IP(src="0.0.0.0", dst="0.0.0.0")/UDP()
pkt_raw = bytearray(str(pkt))
LOG.info("Generated probe is " + str(pkt).encode("HEX"))


class OpenStateEvolution(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(OpenStateEvolution, self).__init__(*args, **kwargs)

    def add_flow(self, datapath, table_id, priority, match, actions):
        if len(actions) > 0:
            inst = [ofparser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
                                  priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        """ Switch sent his features, check if OpenState supported """
        msg = event.msg
        datapath = msg.datapath

        LOG.info("Configuring switch %d..." % datapath.id)

        # Send probe packet to packet generation table
        req = bebaparser.OFPExpMsgAddPktTmp(
            datapath=datapath,
            pkttmp_id=0,
            pkt_data=pkt_raw)
        datapath.send_msg(req)

        req = bebaparser.OFPExpMsgConfigureStatefulTable(
            datapath=datapath,
            table_id=0,
            stateful=1)
        datapath.send_msg(req)

        """ Set lookup extractor = {in_port} """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IN_PORT],
                                             table_id=0)
        datapath.send_msg(req)

        """ Set update extractor = {in_port}  """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IN_PORT],
                                             table_id=0)
        datapath.send_msg(req)

        """ Packet counter_max for designing probe frequency """
        req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
            datapath=datapath,
            table_id=0,
            global_data_variable_id=0,
            value=1234)
        datapath.send_msg(req)

        # match
        match = ofparser.OFPMatch()
        actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        probe_actions = [ofparser.OFPActionSetField(mpls_tc=3),
                         bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR,
                                                                    src_id=0, dst_field=ofproto.OXM_OF_MPLS_LABEL),
                         ofparser.OFPActionOutput(2)]
        insts = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                 bebaparser.OFPInstructionInSwitchPktGen(pkttmp_id=0, actions=probe_actions)]
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0, priority=0, match=match, instructions=insts)
        datapath.send_msg(mod)

        match = ofparser.OFPMatch(eth_type=0x8847)
        actions = [ofparser.OFPActionSetField(mpls_tc=5), ofparser.OFPActionOutput(1)]
        self.add_flow(datapath=datapath, table_id=0, priority=0, match=match, actions=actions)
