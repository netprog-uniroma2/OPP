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
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_dst}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofproto.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		###########################################################################################

		""" Set HF[1]=PKT_LEN [byte]"""
		req = bebaparser.OFPExpMsgHeaderFieldExtract(
				datapath=datapath,
				table_id=0,
				extractor_id=1,
				field=bebaproto.OXM_EXP_PKT_LEN
			)
		datapath.send_msg(req)

		""" Update function: var( [count] , [value_to_be_varianced] , [avg_value] , [var_value]) = (IO1 , IN1 , IO2, IO3) has 4 inputs and 3 outputs
        	OUT1 = FDV[0] = count
       		OUT2 = FDV[1] = avg(IN1)*1000
       		OUT3 = FDV[2] = var(IN1)
       	"""
		match = ofparser.OFPMatch()
		actions = [ofparser.OFPActionOutput(ofproto.OFPP_FLOOD),
			bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_VAR, output_fd_id=0, operand_1_hf_id=1, operand_2_fd_id=1, operand_3_fd_id=2)]
		self.add_flow(datapath=datapath,
				table_id=0,
				priority=0,
				match=match,
				actions=actions)

		""" $ sudo watch --color -n1 dpctl tcp:127.0.0.1:6634 stats-state -c
			mininet> h1 ping h2 -s 100 -c 10
			PKT_LEN = 42+payload => avg(PKT_LEN)=(10*142)/10=142.000
									var(PKT_LEN)=(10*(142**2-142**2)=0

			mininet> h1 ping h2 -s 200 -c 10

			PKT_LEN = 42+payload => avg(PKT_LEN)=(10*142+10*242)/20=191.997~192
									var(PKT_LEN)=(10*(142**2-192**2)+10*(242**2-192**2)/20=2468~2500
		"""
