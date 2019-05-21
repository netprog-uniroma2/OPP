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

		# Constants
		B = 20 # token
		R = 1 # token/sec

		'''
		Assuming B=20 initial tokens and R=1 token/sec

		mininet> h1 ping h2 -i 0.1
		[20 tk + 1 tk/s * X ] - [10 tk/s * X] = 0
		We expect to start losing 9 packet out of 10 after 2.22 sec (starting from around 22th packet)

		Now close and re-open the switch
		mininet> h1 ping h2 -i 0.25
		[20 tk + 1 tk/s * X ] - [4 tk/s * X] = 0
		We expect to start losing 3 packet out of 4 after 6.66 sec (starting from around 26th packet)

		Now close and re-open the switch
		mininet> h1 ping h2 -i 0.5
		[20 tk + 1 tk/s * X ] - [2 tk/s * X] = 0
		We expect to start losing 1 packet out of 2 after 20 sec (starting from around 40th packet)
		'''

		''' HF[0] = OXM_EXP_TIMESTAMP [ms] '''
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=0,
				field=bebaproto.OXM_EXP_TIMESTAMP
			)
		datapath.send_msg(req)

		''' GD[0] = (B-1)*(1/R)*1000 [tok]*[1000 msec/tok]* '''
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=0,
				value=int((B-1)*(1/float(R)*1000))
			)
		datapath.send_msg(req)

		''' GD[1] = (1/R)*1000 [msec]* '''
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=1,
				value=int((1/float(R)*1000))
			)
		datapath.send_msg(req)

		# condition 0: HF[0] >= FDV[0] ?
		# condition 0: now >= Tmin ?
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=0,
				condition_id=0,
				condition=bebaproto.CONDITION_GTE,
				operand_1_hf_id=0,
				operand_2_fd_id=0
			)
		datapath.send_msg(req)

		# condition 1: HF[0] <= FDV[2] ?
		# condition 1: now - Tmin <= (B-1)*(1/R) ?
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=0,
				condition_id=1,
				condition=bebaproto.CONDITION_LTE,
				operand_1_hf_id=0,
				operand_2_fd_id=2
			)
		datapath.send_msg(req)

		# FDV[0] = now()-(B-1)*(1/R) = now() - GDV[0] = Tmin
		# FDV[1] = 0 + GDV[1] = 1/R in ms
		# FDV[2] = HF[0] + GDV[1] = now() + 1/R
		match = ofparser.OFPMatch(eth_type=0x0800,state=0)
		actions = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUB, output_fd_id=0, operand_1_hf_id=0, operand_2_gd_id=0),
			bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=1, operand_1_fd_id=1, operand_2_gd_id=1),
			bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=2, operand_1_hf_id=0, operand_2_gd_id=1),
			bebaparser.OFPExpActionSetState(state=1, table_id=0),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)


		# FDV[0] = FDV[0]+FDV[1]
		# FDV[2] = FDV[2]+FDV[1]
		match = ofparser.OFPMatch(eth_type=0x0800,state=1,condition0=1,condition1=1)
		actions = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=0, operand_1_fd_id=0, operand_2_fd_id=1),
			bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=2, operand_1_fd_id=2, operand_2_fd_id=1),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		# FDV[0] = now()-(B-1)*(1/R) = now() - GDV[0] = Tmin
		# FDV[2] = HF[0] + GDV[1] = now() + 1/R
		match = ofparser.OFPMatch(eth_type=0x0800,state=1,condition0=1,condition1=0)
		actions = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUB, output_fd_id=0, operand_1_hf_id=0, operand_2_gd_id=0),
			bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=2, operand_1_hf_id=0, operand_2_gd_id=1),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)
		
		match = ofparser.OFPMatch(eth_type=0x0800,state=1,condition0=0,condition1=1)
		actions = []
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)