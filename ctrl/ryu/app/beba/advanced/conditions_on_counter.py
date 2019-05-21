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

		""" Set lookup extractor = {eth_dst} """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_DST],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_dst}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_DST],
				table_id=0)
		datapath.send_msg(req)

		###########################################################################################

		""" Set GDV[2]=4 """
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=2,
				value=4
			)
		datapath.send_msg(req)

		""" Set condition 5: FDV[0] >= GDV[2] (i.e. counter >= 4) """
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=0,
				condition_id=5,
				condition=bebaproto.CONDITION_GTE,
				operand_1_fd_id=0,
				operand_2_gd_id=2
			)
		datapath.send_msg(req)

		""" If counter <4 then forward() & Update function: FDV[0] = FDV[0]+1 (i.e. counter = counter+1) """
		match = ofparser.OFPMatch(condition5=0)
		actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD),
		bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=0, operand_1_fd_id=0, operand_2_cost=1)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		""" If counter >=4 then drop() """
		match = ofparser.OFPMatch(condition5=1)
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
		