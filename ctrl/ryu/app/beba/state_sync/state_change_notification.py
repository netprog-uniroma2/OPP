import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser
import array
import struct
import binascii


LOG = logging.getLogger('app.openstate.maclearning.state_sync')

# Number of switch ports
N = 4

LOG.info("Support max %d ports per switch" % N)

devices=[]

class OSMacLearning(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(OSMacLearning, self).__init__(*args, **kwargs)

	def add_flow(self, datapath, table_id, priority, match, actions):
		if len(actions) > 0:
			inst = [ofparser.OFPInstructionActions(
					ofp.OFPIT_APPLY_ACTIONS, actions)]
		else:
			inst = []
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, event):

		""" Switche sent his features, check if OpenState supported """
		msg = event.msg
		datapath = msg.datapath
		devices.append(datapath)
	

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
				fields=[ofp.OXM_OF_ETH_DST],
				table_id=0)
		datapath.send_msg(req)

		""" Set update extractor = {eth_src}  """
		req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
				command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
				fields=[ofp.OXM_OF_ETH_SRC],
				table_id=0)
		datapath.send_msg(req)

		# for each input port, for each state
		for i in range(1, N+1):
			for s in range(N+1):
				match = ofparser.OFPMatch(in_port=i, state=s)
				if s == 0:
					out_port = ofp.OFPP_FLOOD
				else:
					out_port = s

				actions = [
					bebaparser.OFPExpActionSetState(state=i, table_id=0, hard_timeout=10),
					ofparser.OFPActionOutput(out_port)
					#,ofparser.OFPActionOutput(ofp.OFPP_CONTROLLER,
					#ofp.OFPCML_NO_BUFFER)
				]

				self.add_flow(datapath=datapath, table_id=0, priority=0, match=match, actions=actions)
				
	@set_ev_cls(ofp_event.EventOFPExperimenter, MAIN_DISPATCHER)
	def packet_in_handler(self, event):
		msg = event.msg
		
		if(msg.experimenter==0xBEBABEBA and msg.exp_type==bebaproto.OFPT_EXP_STATE_CHANGED):
			data1 = msg.data[:struct.calcsize("!IIIII")]

			# StateSync: The state notification message contains the following fields
			(table_id, old_state, new_state, state_mask, key_len) = struct.unpack("!IIIII", data1)
			print("  Table ID: "+str(table_id))
			print(" Old state: "+str(old_state))
			print(" New state: "+str(new_state))
			print("Key length: "+str(key_len))
			data2 = msg.data[struct.calcsize("!IIIII"):]
			key = data2[:key_len]
			print binascii.hexlify(key)
			print("************")
