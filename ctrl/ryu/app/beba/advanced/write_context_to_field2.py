import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser

LOG = logging.getLogger('app.beba.evolution')


class BebaEvolution(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(BebaEvolution, self).__init__(*args, **kwargs)

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

		""" switch sent his features, check if Beba supported """
		msg = event.msg
		datapath = msg.datapath

		LOG.info("Configuring switch %d..." % datapath.id)

		""" Set table 0 as stateful """
		req = bebaparser.OFPExpMsgConfigureStatefulTable(
				datapath=datapath,
				table_id=1,
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {eth_src} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=1)
		datapath.send_msg(req)

		""" Set update extractor = {eth_src}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=1)
		datapath.send_msg(req)

		###########################################################################################
		
		""" Set GDV[3]=123 """
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=1,
				global_data_variable_id=3,
				value=123
			)
		datapath.send_msg(req)

		""" If any then push(MPLS) & GoToTable(1) """
		match = ofparser.OFPMatch()
		actions = [ofparser.OFPActionPushMpls()]
		inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions),
			ofparser.OFPInstructionGotoTable(1)]
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
								priority=0, match=match, instructions=inst)
		datapath.send_msg(mod)

		""" If MPLS then:	forward()
							update function: FDV[2] = F[2]+1 (i.e. counter = counter+1)
							MPLS_LABEL = GDV[2]
							MPLS_TC = GDV[3]
		"""

		match = ofparser.OFPMatch(eth_type=0x8847)
		actions = [bebaparser.OFPExpActionSetDataVariable(table_id=1, opcode=bebaproto.OPCODE_SUM, output_fd_id=2, operand_1_fd_id=2, operand_2_cost=1),
		bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_FLOW_DATA_VAR,src_id=2,dst_field=ofproto.OXM_OF_MPLS_LABEL),
		bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR,src_id=3,dst_field=ofproto.OXM_OF_MPLS_TC),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=1,
				priority=0,
				match=match,
				actions=actions)

		"""
		mininet> xterm h2
		h2# tcpdump -n
		mininet> h1 ping h2

		Packets should have an incremental MPLS label and a MPLS exp 123
		
		"""
		