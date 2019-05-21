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

		""" Switch sent his features, check if Beba supported """
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
		""" Set GDV[1]=0 """
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=1,
				value=0
			)
		datapath.send_msg(req)

		""" Set GDV[2]=2 """
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=2,
				value=2
			)
		datapath.send_msg(req)

		""" Set GDV[3]=5 """
		req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
				datapath=datapath,
				table_id=0,
				global_data_variable_id=3,
				value=5
			)
		datapath.send_msg(req)

		""" Update function: FDV[2] = GDV[2]*10 + 1*4 + GDV[1]*5 - GDV[3]*6 = 2*30 + 1*4 + 0*5 - 5*6 = 34 """
		match = ofparser.OFPMatch()
		actions = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_POLY_SUM, output_fd_id=2,
			operand_1_gd_id=2, operand_2_cost=1, operand_3_gd_id=1, operand_4_gd_id=3,
			coeff_1=30,coeff_2=4,coeff_3=5,coeff_4=-6),
			ofparser.OFPActionOutput(ofproto.OFPP_FLOOD)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)
		
		"""
		mininet> h1 ping h2 -c1
		$ sudo watch --color -n1 dpctl tcp:127.0.0.1:6634 stats-state -c
		FDV[2] should be 34
		"""