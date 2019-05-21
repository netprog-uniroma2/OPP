import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

LOG = logging.getLogger('app.beba.ddos')

class BebaDDoS(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(BebaDDoS, self).__init__(*args, **kwargs)

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

		""" Switche sent his features, check if Beba supported """
		msg = event.msg
		datapath = msg.datapath

		LOG.info("Configuring switch %d..." % datapath.id)
		
		
		for table in range(0,2):
			""" Set tables as stateful """
			req = bebaparser.OFPExpMsgConfigureStatefulTable(datapath=datapath, 
					table_id=table, 
					stateful=1)
			datapath.send_msg(req)

			""" Set lookup extractor = {ip_src, ip_dst, tcp_src, tcp_dst} """
			req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, 									
					command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR, 
					fields=[ofproto.OXM_OF_IPV4_SRC,ofproto.OXM_OF_IPV4_DST,ofproto.OXM_OF_TCP_SRC,ofproto.OXM_OF_TCP_DST], 
					table_id=table)
			datapath.send_msg(req)

			""" Set update extractor = {ip_src, ip_dst, tcp_src, tcp_dst} (same as lookup) """
			req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, 
					command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR, 
					fields=[ofproto.OXM_OF_IPV4_SRC,ofproto.OXM_OF_IPV4_DST,ofproto.OXM_OF_TCP_SRC,ofproto.OXM_OF_TCP_DST],
					table_id=table)
			datapath.send_msg(req)


		""" Configure meter 1 """
		b1 = ofparser.OFPMeterBandDscpRemark(rate=10, prec_level=1)
		req = ofparser.OFPMeterMod(datapath, command=ofproto.OFPMC_ADD, flags=ofproto.OFPMF_PKTPS, meter_id=1, bands=[b1])
		datapath.send_msg(req)

		""" Table 0 """
		match = ofparser.OFPMatch(eth_type=0x0800,ipv4_dst="10.0.0.2",state=0)
		actions = [bebaparser.OFPExpActionSetState(state=1, table_id=0, idle_timeout=30)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), ofparser.OFPInstructionMeter(meter_id=1),
				ofparser.OFPInstructionGotoTable(table_id=1)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=10, match=match, instructions=inst)
		datapath.send_msg(mod)

		match = ofparser.OFPMatch(eth_type=0x0800,ipv4_dst="10.0.0.2",state=1)
		inst = [ofparser.OFPInstructionGotoTable(table_id=1)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=10, match=match, instructions=inst)
		datapath.send_msg(mod)

		match = ofparser.OFPMatch(eth_type=0x0800,ipv4_dst="10.0.0.1")
		actions = [ofparser.OFPActionOutput(1)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=10, match=match, instructions=inst)
		datapath.send_msg(mod)

		""" Table 1 """
		match = ofparser.OFPMatch(state=0,eth_type=0x0800,ipv4_dst="10.0.0.2",ip_dscp=10)
		actions = [ofparser.OFPActionOutput(2)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=10, match=match, instructions=inst)
		datapath.send_msg(mod)

		match = ofparser.OFPMatch(eth_type=0x0800,ipv4_dst="10.0.0.2",ip_dscp=12)
		actions = [bebaparser.OFPExpActionSetState(state=1, table_id=1, idle_timeout=30)]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=10, match=match, instructions=inst)
		datapath.send_msg(mod)

		match = ofparser.OFPMatch(state=1,eth_type=0x0800,ipv4_dst="10.0.0.2", ip_dscp=10)
		actions = []
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=1,
								priority=10, match=match, instructions=inst)
		datapath.send_msg(mod)

