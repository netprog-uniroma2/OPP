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

		""" Set lookup extractor = {eth_src} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_src}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		###########################################################################################

		""" Set HF[1]=TIMESTAMP [ms] """
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=1,
				field=bebaproto.OXM_EXP_TIMESTAMP
			)
		datapath.send_msg(req)

		""" Set GDV[3]=5500 """
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=3,
				value=3500
			)
		datapath.send_msg(req)

		""" Update function: FDV[0] =  HF[1] + GDV[3] (i.e. deadline = now() + TIMEOUT) """
		match = ofparser.OFPMatch(state=0)
		actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD),
					bebaparser.OFPExpActionSetState(state=1, table_id=0),
					bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=0, operand_1_hf_id=1, operand_2_gd_id=3)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		""" Set condition 3: HF[1] < FDV[0] (i.e. now() < deadline) """
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=0,
				condition_id=3,
				condition=bebaproto.CONDITION_LT,
				operand_1_hf_id=1,
				operand_2_fd_id=0
			)
		datapath.send_msg(req)

		""" If now() < deadline then drop() """
		match = ofparser.OFPMatch(state=1,condition3=1)
		actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		""" If now() >= deadline then drop() & state transition """
		match = ofparser.OFPMatch(state=1,condition3=0)
		actions = [bebaparser.OFPExpActionSetState(state=2, table_id=0),]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		""" drop() """
		match = ofparser.OFPMatch(state=2)
		actions = []
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		"""
		$ sudo mn --topo single,4 --switch user --controller remote --mac --arp
		mininet> h1 ping h2 -c10
		It should drop all the packets from the 5-th 
		"""
		