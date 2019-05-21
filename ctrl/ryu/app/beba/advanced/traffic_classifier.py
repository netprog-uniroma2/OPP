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
				table_id=0,
				stateful=1)
		datapath.send_msg(req)

		""" Set lookup extractor = {ip_src} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {ip_src}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_IPV4_SRC],
				table_id=0)
		datapath.send_msg(req)

		###########################################################################################

		"""
		The traffic classifier extracts 3 features:  avg_pkt_len [bytes], var_pkt_len [bytes^2], tot_flow_bytes [bytes].
		The training phase lasts 10 seconds.
		A flow in state 1 is in training phase. After 10 seconds, the flow is classified to state 2 or 3.
		Classification conditions are

		c1 AND c3 --> state = 3
		c1 AND not c3 --> state = 2
		not c1 AND not c2 --> state = 2
		not c1 and c2 --> state = 3

		where
		c1: var_pkt_len > 1575
		c2: tot_flow_byte > 203
		c3: avg_pkt_len <= 306

		thus
		var_pkt_len > 1575  AND  avg_pkt_len <= 306  --> state = 3
		var_pkt_len > 1575  AND  avg_pkt_len > 306  --> state = 2
		var_pkt_len <= 1575  AND  tot_flow_byte <= 203  --> state = 2
		var_pkt_len <= 1575  AND  tot_flow_byte > 203  --> state = 3

		$ sudo dpctl tcp:127.0.0.1:6634 stats-state -c
		mininet> h1 ping h2 -c15
		Flow with IP SRC 10.0.0.1 is of type 2 (state=3)

		mininet> h3 ping h4 -c2; sleep 9; ping h4 -c5
		Flow with IP SRC 10.0.0.3 is of type 1 (state=2)
		"""

		''' HF[0] = OXM_EXP_TIMESTAMP [ms] '''
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=0,
				field=bebaproto.OXM_EXP_TIMESTAMP
			)
		datapath.send_msg(req)

		''' HF[1] = OXM_EXP_PKT_LEN'''
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=1,
				field=bebaproto.OXM_EXP_PKT_LEN
			)
		datapath.send_msg(req)


		''' GDV[0] = 10 [sec] '''
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=0,
				value=10000
			)
		datapath.send_msg(req)

		''' GDV[1] = 306.000 '''
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=1,
				value=306000
			)
		datapath.send_msg(req)

		''' GDV[2] = 1575 '''
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=2,
				value=1575
			)
		datapath.send_msg(req)

		''' GDV[3] = 203 '''
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=3,
				value=203
			)
		datapath.send_msg(req)

		# condition 0: HF[0] >= FDV[4] ?
		# condition 0: now >= measurement window expiration time ?
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=0,
				condition_id=0,
				condition=bebaproto.CONDITION_GTE,
				operand_1_hf_id=0,
				operand_2_fd_id=4
			)
		datapath.send_msg(req)

		# condition 1: FDV[2] > GDV[2] ?
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=0,
				condition_id=1,
				condition=bebaproto.CONDITION_GT,
				operand_1_fd_id=2,
				operand_2_gd_id=2
			)
		datapath.send_msg(req)

		# condition 2: FDV[3] > GDV[3] ?
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=0,
				condition_id=2,
				condition=bebaproto.CONDITION_GT,
				operand_1_fd_id=3,
				operand_2_gd_id=3
			)
		datapath.send_msg(req)

		# condition 3: FDV[1] <= GDV[1] ?
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=0,
				condition_id=3,
				condition=bebaproto.CONDITION_LTE,
				operand_1_fd_id=1,
				operand_2_gd_id=1
			)
		datapath.send_msg(req)	

		# FDV[4] = now() + 10 = HF[0] + GDV[0] = Tmin
		# FDV[2] = var(count,pkt_len,avg,var);
		# FDV[3] = FDV[3] + HF[0]
		match = ofparser.OFPMatch(eth_type=0x0800,state=0)
		actions = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=4, operand_1_hf_id=0, operand_2_gd_id=0),
			bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_VAR, output_fd_id=0, operand_1_hf_id=1, operand_2_fd_id=1, operand_3_fd_id=2),
			bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=3, operand_1_fd_id=3, operand_2_hf_id=1),
			bebaparser.OFPExpActionSetState(state=1, table_id=0),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		match = ofparser.OFPMatch(eth_type=0x0800,state=1,condition0=0)
		actions = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_VAR, output_fd_id=0, operand_1_hf_id=1, operand_2_fd_id=1, operand_3_fd_id=2),
			bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=3, operand_1_fd_id=3, operand_2_hf_id=1),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		match = ofparser.OFPMatch(eth_type=0x0800,state=1,condition0=1,condition1=1,condition3=1)
		actions = [bebaparser.OFPExpActionSetState(state=3, table_id=0),
			ofparser.OFPActionSetField(ip_dscp=0),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		match = ofparser.OFPMatch(eth_type=0x0800,state=1,condition0=1,condition1=1,condition3=0)
		actions = [bebaparser.OFPExpActionSetState(state=2, table_id=0),
			ofparser.OFPActionSetField(ip_dscp=10),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		match = ofparser.OFPMatch(eth_type=0x0800,state=1,condition0=1,condition1=0,condition2=0)
		actions = [bebaparser.OFPExpActionSetState(state=2, table_id=0),
			ofparser.OFPActionSetField(ip_dscp=10),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		match = ofparser.OFPMatch(eth_type=0x0800,state=1,condition0=1,condition1=0,condition2=1)
		actions = [bebaparser.OFPExpActionSetState(state=3, table_id=0),
			ofparser.OFPActionSetField(ip_dscp=0),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		match = ofparser.OFPMatch(eth_type=0x0800,state=2)
		actions = [ofparser.OFPActionSetField(ip_dscp=10),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		match = ofparser.OFPMatch(eth_type=0x0800,state=3)
		actions = [ofparser.OFPActionSetField(ip_dscp=0),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)