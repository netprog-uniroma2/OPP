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

		""" Set HF[0]=IN_PORT """
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=0,
				field=ofproto.OXM_OF_IN_PORT
			)
		datapath.send_msg(req)

		""" Set GDV[2]=4 """
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=2,
				value=4
			)
		datapath.send_msg(req)

		""" Set condition 5: HF[0] >= GDV[2] (i.e. IN_PORT >= 4) """
		req = bebaparser.OFPExpMsgSetCondition(
				datapath=datapath,
				table_id=0,
				condition_id=5,
				condition=bebaproto.CONDITION_GTE,
				operand_1_hf_id=0,
				operand_2_gd_id=2
			)
		datapath.send_msg(req)

		
		""" If IN_PORT >= 4 then drop() """
		match = ofparser.OFPMatch(condition5=1)
		actions = []
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		""" If IN_PORT < 4 then forward() """
		match = ofparser.OFPMatch(condition5=0)
		actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)
		
		"""
		mininet> pingall
		It should drop all packets coming from port>=4
		"""