import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser
from ryu.lib import hub
from scapy.contrib.mpls import MPLS
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
import matplotlib.pyplot as plt

LOG = logging.getLogger('app.openstate.evolution')

RTT = 0.08   # Tuning parameter for flowlet division in seconds

PROBE_FREQ = 50  # in milliseconds

REQ_FREQ = 0.5

ALPHA = bebaproto.EWMA_PARAM_0750  # alpha parameter for the ewma filter

UPPER_PORTS = [1, 2]
DOWN_PORTS = [3]
LEAVES = [1, 2, 3]
HOSTS_NUMBER = 1
MAC_ADDRS = ["00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:03"]

# Probe packet generated with scapy
pkt = Ether(src="10:00:00:00:00:01", dst="20:00:00:00:00:02")/MPLS(ttl=64)/IP(ttl=64, dst='10.0.0.1', src='2.2.2.2')
pkt_raw = bytearray(str(pkt))
LOG.info("Generated probe is " + str(pkt).encode("HEX"))


class OpenStateEvolution(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(OpenStateEvolution, self).__init__(*args, **kwargs)
        self.datapaths = []
        self.output_files = ["leaf1.txt", "leaf2.txt", "leaf3.txt"]
        self.monitor_thread = hub.spawn(self._monitor)
        self.time = 0

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
        """ Switch sent his features, check if OpenState supported """
        msg = event.msg
        datapath = msg.datapath

        LOG.info("Configuring switch %d..." % datapath.id)

        if datapath.id in LEAVES:
            self.install_leaves(datapath)
            self.datapaths.append(datapath)
        else:
            self.install_spines(datapath)

    def install_leaves(self, datapath):
        # Send probe packet to packet generation table
        req = bebaparser.OFPExpMsgAddPktTmp(
            datapath=datapath,
            pkttmp_id=0,
            pkt_data=pkt_raw)
        datapath.send_msg(req)

        ##################################### TABLE 0: DISPATCHING ##################################################

        ######################### TABLE 0 CONFIG ###############
        req = bebaparser.OFPExpMsgConfigureStatefulTable(
            datapath=datapath,
            table_id=0,
            stateful=1)
        datapath.send_msg(req)

        """ Set lookup extractor = {eth_dst} """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IN_PORT],
                                             table_id=0)
        datapath.send_msg(req)

        """ Set update extractor = {eth_dst}  """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IN_PORT],
                                             table_id=0)
        datapath.send_msg(req)

        """ Field extractor for mpls label """
        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=0,
            extractor_id=0,
            field=ofproto.OXM_OF_MPLS_LABEL)
        datapath.send_msg(req)

        """ Field extractor for timestamp """
        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=0,
            extractor_id=1,
            field=bebaproto.OXM_EXP_TIMESTAMP)
        datapath.send_msg(req)

        """ Packet counter_max for designing probe frequency """
        req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
            datapath=datapath,
            table_id=0,
            global_data_variable_id=0,
            value=PROBE_FREQ)
        datapath.send_msg(req)

        """ Condition C0: if counter reaches counter_max, then trigger probe sending """
        req = bebaparser.OFPExpMsgSetCondition(
            datapath=datapath,
            table_id=0,
            condition_id=0,
            condition=bebaproto.CONDITION_GTE,
            operand_1_fd_id=0,
            operand_2_gd_id=0)
        datapath.send_msg(req)

        req = bebaparser.OFPExpMsgSetCondition(
            datapath=datapath,
            table_id=0,
            condition_id=3,
            condition=bebaproto.CONDITION_GTE,
            operand_1_fd_id=0,
            operand_2_gd_id=0)
        datapath.send_msg(req)

        ##################################### TABLE 0 FLOWS ##################################################

        """ RECEIVE PROBE ACTION """
        """ When a probe is received tab0 sends it to tab3"""
        """ match: 	MPLS """
        """ no action """
        """ instruction: goto tab3"""

        match = ofparser.OFPMatch(eth_type=0x8847)
        instructions = [ofparser.OFPInstructionGotoTable(3)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath,
            table_id=0,
            priority=200,
            match=match,
            instructions=instructions)
        datapath.send_msg(mod)

        """ For packets from down ports (attached to hosts): go to ToR Discovery table (1) """
        for i in DOWN_PORTS:
            match = ofparser.OFPMatch(in_port=i)
            instructions = [ofparser.OFPInstructionGotoTable(1)]
            mod = ofparser.OFPFlowMod(
                datapath=datapath,
                table_id=0,
                priority=10,
                match=match,
                instructions=instructions)
            datapath.send_msg(mod)

        match = ofparser.OFPMatch()
        instructions = [ofparser.OFPInstructionGotoTable(2)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath,
            table_id=0,
            priority=0,
            match=match,
            instructions=instructions)
        datapath.send_msg(mod)

        # using low bitrate flows to refresh the estimates. For testing purposes only
        for i in [0, 1]:
            match = ofparser.OFPMatch(in_port=3, eth_type=0x0800, ip_proto=6, tcp_dst=10000 + i)
            actions = [ofparser.OFPActionOutput(i + 1)]
            self.add_flow(datapath=datapath, table_id=0, priority=200, match=match, actions=actions)

            match = ofparser.OFPMatch(in_port=3, eth_type=0x0800, ip_proto=6, tcp_src=10000 + i)
            actions = [ofparser.OFPActionOutput(i + 1)]
            self.add_flow(datapath=datapath, table_id=0, priority=200, match=match, actions=actions)

        ######################## TABLE 1 ToR DISCOVERY  #########################################################

        # this cycle writes metadata specifying to which leaf belongs the packet
        for i in LEAVES:
            if i != datapath.id:
                match = ofparser.OFPMatch(eth_dst=MAC_ADDRS[i - 1])
                instructions = [ofparser.OFPInstructionWriteMetadata(metadata=i, metadata_mask=0xffffffff),
                                ofparser.OFPInstructionGotoTable(3)]
                mod = ofparser.OFPFlowMod(
                    datapath=datapath,
                    table_id=1,
                    priority=0,
                    match=match,
                    instructions=instructions)
                datapath.send_msg(mod)

        ######################### TABLE 2: ACTIVE PROBING ######################################################

        ################### TABLE 2 CONFIG #########

        req = bebaparser.OFPExpMsgConfigureStatefulTable(
            datapath=datapath,
            table_id=2,
            stateful=1)
        datapath.send_msg(req)

        """ Set lookup extractor = {IN_PORT} """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IN_PORT],
                                             table_id=2)
        datapath.send_msg(req)

        """ Set update extractor = {IN_PORT}  """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IN_PORT],
                                             table_id=2)
        datapath.send_msg(req)

        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=2,
            extractor_id=1,
            field=bebaproto.OXM_EXP_TIMESTAMP
        )
        datapath.send_msg(req)

        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=2,
            extractor_id=2,
            field=bebaproto.OXM_EXP_PKT_LEN)
        datapath.send_msg(req)

        req = bebaparser.OFPExpMsgSetCondition(
            datapath=datapath,
            condition=bebaproto.CONDITION_GTE,
            condition_id=0,
            table_id=2,
            operand_1_hf_id=1,
            operand_2_fd_id=4)
        datapath.send_msg(req)

        ############################### TABLE 2 FLOWS #############################

        match = ofparser.OFPMatch(state=0)
        actions = [bebaparser.OFPExpActionSetState(table_id=2, state=1, idle_timeout=2),
                   # saves timestamp
                   bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUM, output_fd_id=4,
                                                          operand_1_hf_id=1, operand_2_cost=PROBE_FREQ),
                   ofparser.OFPActionOutput(3)]
        self.add_flow(datapath=datapath, table_id=2, priority=500, match=match, actions=actions)

        """ For every packet coming from spine ports, calculates ewma """
        for i in UPPER_PORTS:
            # simply ewma measuring
            match = ofparser.OFPMatch(state=1, in_port=i, condition0=1)
            actions_ewma_1 = [  # calculates deltaT: FDV[1]=HF[1]-FDV[0]=TS_NOW - TS_LAST
                bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUB, output_fd_id=1,
                                                       operand_1_hf_id=1, operand_2_fd_id=0),
                # calculates rate: R = (bytes / deltaT_ms) * 8 [kb/s]
                bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_MUL, output_fd_id=2,
                                                       operand_1_fd_id=2, operand_2_cost=8),
                # stores the result in FDV[3]: THE FLOW ESTIMATED RATE
                bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_DIV, output_fd_id=2,
                                                       operand_1_fd_id=2, operand_2_fd_id=1),
                # calculates ewma
                bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_EWMA, output_fd_id=3,
                                                       operand_1_fd_id=3, operand_2_cost=ALPHA,
                                                       operand_3_fd_id=2),
                # saves current timestamp
                bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUM, output_fd_id=0,
                                                       operand_1_hf_id=1, operand_2_cost=0),
                # saves timestamp + probe freq
                bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUM, output_fd_id=4,
                                                       operand_1_hf_id=1, operand_2_cost=PROBE_FREQ),
                # reset byte counter
                bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUB, output_fd_id=2,
                                                       operand_1_fd_id=2, operand_2_fd_id=2),
                # saves in GDV[i] the ewma
                bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUM, output_gd_id=i,
                                                       operand_1_fd_id=3, operand_2_cost=0)]
            # actions for the packet
            actions = actions_ewma_1 + [ofparser.OFPActionOutput(3)]
            # action group for the probes
            probe_actions1 = [ofparser.OFPActionSetField(mpls_tc=datapath.id),  # the GDV[i]
                              bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR,
                                                                         src_id=i, dst_field=ofproto.OXM_OF_MPLS_LABEL),
                              ofparser.OFPActionOutput(i)]
            probe_actions2 = [ofparser.OFPActionSetField(mpls_tc=datapath.id),  # the GDV[other]
                              bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR,
                                                                         src_id=(1 if i == 2 else 2),
                                                                         dst_field=ofproto.OXM_OF_MPLS_LABEL),
                              ofparser.OFPActionOutput((1 if i == 2 else 2))]
            # apply packet actions
            insts = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                     # apply packet generation
                     bebaparser.OFPInstructionInSwitchPktGen(pkttmp_id=0, actions=probe_actions1),
                     bebaparser.OFPInstructionInSwitchPktGen(pkttmp_id=0, actions=probe_actions2)]
            mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2, priority=30, match=match, instructions=insts)
            datapath.send_msg(mod)

            match = ofparser.OFPMatch(state=1, in_port=i, condition0=0)
            actions_ewma_2 = [bebaparser.OFPExpActionSetDataVariable(table_id=2, opcode=bebaproto.OPCODE_SUM,
                                                                     output_fd_id=2, operand_1_fd_id=2,
                                                                     operand_2_hf_id=2)]
            self.add_flow(datapath=datapath, table_id=2, priority=30, match=match,
                          actions=actions_ewma_2 + [ofparser.OFPActionOutput(3)])

            # using low bitrate flows to refresh the estimates. For testing purposes only
            for j in [0, 1]:
                match = ofparser.OFPMatch(in_port=i, eth_type=0x0800, ip_proto=6, tcp_dst=10000 + j, condition0=1)
                actions = actions_ewma_1 + [ofparser.OFPActionOutput(3)]
                self.add_flow(datapath=datapath, table_id=2, priority=150, match=match, actions=actions)

                match = ofparser.OFPMatch(in_port=i, eth_type=0x0800, ip_proto=6, tcp_src=10000 + j, condition0=1)
                actions = actions_ewma_1 + [ofparser.OFPActionOutput(3)]
                self.add_flow(datapath=datapath, table_id=2, priority=150, match=match, actions=actions)

                match = ofparser.OFPMatch(in_port=i, eth_type=0x0800, ip_proto=6, tcp_dst=10000 + j, condition0=0)
                actions = actions_ewma_2 + [ofparser.OFPActionOutput(3)]
                self.add_flow(datapath=datapath, table_id=2, priority=150, match=match, actions=actions)

                match = ofparser.OFPMatch(in_port=i, eth_type=0x0800, ip_proto=6, tcp_src=10000 + j, condition0=0)
                actions = actions_ewma_2 + [ofparser.OFPActionOutput(3)]
                self.add_flow(datapath=datapath, table_id=2, priority=150, match=match, actions=actions)

        ######################## TABLE 3: FORWARDING ##############################################################

        ######################## TABLE 3 CONFIG #####################################################################


        ##### GDV[1] contains path utilization to dest 1 on port 1
        ##### GDV[2] contains path utilization to dest 2 on port 1
        ##### GDV[3] contains path utilization to dest 1 on port 2
        ##### GDV[4] contains path utilization to dest 2 on port 2

        req = bebaparser.OFPExpMsgConfigureStatefulTable(
            datapath=datapath,
            table_id=3,
            stateful=1)
        datapath.send_msg(req)

        """ Set lookup extractor """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IPV4_DST,
                                                     ofproto.OXM_OF_TCP_SRC, ofproto.OXM_OF_TCP_DST],
                                             table_id=3)
        datapath.send_msg(req)

        """ Set update extractor """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IPV4_SRC, ofproto.OXM_OF_IPV4_DST,
                                                     ofproto.OXM_OF_TCP_SRC, ofproto.OXM_OF_TCP_DST],
                                             table_id=3)
        datapath.send_msg(req)

        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=3,
            extractor_id=0,
            field=ofproto.OXM_OF_MPLS_LABEL)
        datapath.send_msg(req)

        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=3,
            extractor_id=1,
            field=bebaproto.OXM_EXP_TIMESTAMP
        )
        datapath.send_msg(req)

        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=3,
            extractor_id=2,
            field=bebaproto.OXM_EXP_PKT_LEN)
        datapath.send_msg(req)

        #################################### TABLE 3 FLOWS ###################################

        # many conditions as the number of LEAVES-1
        # for i in LEAVES except datapath.id: create condition[i]

        # in case of 2 Spines
        for destLeaf in [1, 2]:
            # C[destLeaf]: in which port there is less utilization for that destination?
            req = bebaparser.OFPExpMsgSetCondition(
                datapath=datapath,
                condition=bebaproto.CONDITION_LTE,
                condition_id=destLeaf,
                table_id=3,
                operand_1_gd_id=destLeaf,
                operand_2_gd_id=destLeaf + 2)
            datapath.send_msg(req)

        # leaf number dependent flows
        if datapath.id == 1:
            # LEAF 1 new flows: fetch the destination leaf and check the appropriate condition
            match1true = ofparser.OFPMatch(metadata=2, condition1=1, state=0)  # dst=2, port 1
            match2true = ofparser.OFPMatch(metadata=3, condition2=1, state=0)  # dst=3, port 1
            match1false = ofparser.OFPMatch(metadata=2, condition1=0, state=0)  # dst=2, port 2
            match2false = ofparser.OFPMatch(metadata=3, condition2=0, state=0)  # dst=3, port 2
        elif datapath.id == 2:
            # LEAF 2 new flows: fetch the destination leaf and check the appropriate condition
            match1true = ofparser.OFPMatch(metadata=1, condition1=1, state=0)  # dst=1, port 1
            match2true = ofparser.OFPMatch(metadata=3, condition2=1, state=0)  # dst=3, port 1
            match1false = ofparser.OFPMatch(metadata=1, condition1=0, state=0)  # dst=1, port 2
            match2false = ofparser.OFPMatch(metadata=3, condition2=0, state=0)  # dst=3, port 2
        elif datapath.id == 3:
            # LEAF 3 new flows: fetch the destination leaf and check the appropriate condition
            match1true = ofparser.OFPMatch(metadata=1, condition1=1, state=0)  # dst=1, port 1
            match2true = ofparser.OFPMatch(metadata=2, condition2=1, state=0)  # dst=2, port 1
            match1false = ofparser.OFPMatch(metadata=1, condition1=0, state=0)  # dst=1, port 2
            match2false = ofparser.OFPMatch(metadata=2, condition2=0, state=0)  # dst=2, port 2

        # if port 1 is better, set_state(1) and output 1
        actions_true = [bebaparser.OFPExpActionSetState(state=1, table_id=3, idle_timeout=RTT),
                        ofparser.OFPActionOutput(1)]

        # if port 2 is better, set_state(2) and output 2
        actions_false = [bebaparser.OFPExpActionSetState(state=2, table_id=3, idle_timeout=RTT),
                         ofparser.OFPActionOutput(2)]

        self.add_flow(datapath=datapath, table_id=3, priority=20, match=match1true, actions=actions_true)
        self.add_flow(datapath=datapath, table_id=3, priority=20, match=match2true, actions=actions_true)
        self.add_flow(datapath=datapath, table_id=3, priority=20, match=match1false, actions=actions_false)
        self.add_flow(datapath=datapath, table_id=3, priority=20, match=match2false, actions=actions_false)

        """ extract external probes' data and store in GDVs """

        match = ofparser.OFPMatch(eth_type=0x8847, mpls_tc=datapath.id)
        self.add_flow(datapath=datapath, table_id=3, priority=300, match=match, actions=[])

        for i in UPPER_PORTS:
            for leafNo in LEAVES:
                if leafNo != datapath.id:
                    match = ofparser.OFPMatch(in_port=i, eth_type=0x8847, mpls_tc=leafNo)
                    """ actions: save in GDVs external probes' data """
                    if datapath.id == 1:
                        if leafNo == 2:
                            actions = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM,
                                                                              output_gd_id=(1 if i == 1 else 3),
                                                                              operand_1_hf_id=0, operand_2_cost=0)]
                        elif leafNo == 3:
                            actions = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM,
                                                                              output_gd_id=(2 if i == 1 else 4),
                                                                              operand_1_hf_id=0, operand_2_cost=0)]
                    elif datapath.id == 2:
                        if leafNo == 1:
                            actions = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM,
                                                                              output_gd_id=(1 if i == 1 else 3),
                                                                              operand_1_hf_id=0, operand_2_cost=0)]
                        elif leafNo == 3:
                            actions = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM,
                                                                              output_gd_id=(2 if i == 1 else 4),
                                                                              operand_1_hf_id=0, operand_2_cost=0)]
                    elif datapath.id == 3:
                        if leafNo == 1:
                            actions = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM,
                                                                              output_gd_id=(1 if i == 1 else 3),
                                                                              operand_1_hf_id=0, operand_2_cost=0)]
                        elif leafNo == 2:
                            actions = [bebaparser.OFPExpActionSetDataVariable(table_id=3, opcode=bebaproto.OPCODE_SUM,
                                                                              output_gd_id=(2 if i == 1 else 4),
                                                                              operand_1_hf_id=0, operand_2_cost=0)]

                    self.add_flow(datapath=datapath, table_id=3, priority=200, match=match, actions=actions)

        for s in UPPER_PORTS:
            for metadata in LEAVES:
                # normal conditions
                match = ofparser.OFPMatch(in_port=3, state=s, metadata=metadata)  # , condition4=0)
                actions = [ofparser.OFPActionOutput(s)]
                self.add_flow(datapath=datapath, table_id=3, priority=30, match=match, actions=actions)


    ###################### SPINES ######################################################################################

    def install_spines(self, datapath):
        ######################### TABLE 1 CONFIG ###############
        req = bebaparser.OFPExpMsgConfigureStatefulTable(
            datapath=datapath,
            table_id=0,
            stateful=1)
        datapath.send_msg(req)

        """ Set lookup extractor = {eth_dst} """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IN_PORT],
                                             table_id=0)
        datapath.send_msg(req)

        """ Set update extractor = {eth_dst}  """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IN_PORT],
                                             table_id=0)
        datapath.send_msg(req)

        # mpls extractor
        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=0,
            extractor_id=0,
            field=ofproto.OXM_OF_MPLS_LABEL
        )
        datapath.send_msg(req)

        # timestamp extractor
        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=0,
            extractor_id=1,
            field=bebaproto.OXM_EXP_TIMESTAMP
        )
        datapath.send_msg(req)

        # packet length extractor
        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=0,
            extractor_id=2,
            field=bebaproto.OXM_EXP_PKT_LEN)
        datapath.send_msg(req)

        req = bebaparser.OFPExpMsgSetCondition(
            datapath=datapath,
            condition=bebaproto.CONDITION_GTE,
            condition_id=0,
            table_id=0,
            operand_1_hf_id=1,
            operand_2_fd_id=4)
        datapath.send_msg(req)

        ########################### TABLE 1: MEASURING #####################

        for i in LEAVES:
            if i == 1:
                out_ports = [2, 3]
            elif i == 2:
                out_ports = [1, 3]
            elif i == 3:
                out_ports = [1, 2]

            buckets = []
            actions = [
                bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR, src_id=4,
                                                           dst_field=ofproto.OXM_OF_MPLS_LABEL),
                ofparser.OFPActionOutput(out_ports[0])]
            buckets.append(ofparser.OFPBucket(actions=actions))

            actions = [
                bebaparser.OFPExpActionWriteContextToField(src_type=bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR, src_id=5,
                                                           dst_field=ofproto.OXM_OF_MPLS_LABEL),
                ofparser.OFPActionOutput(out_ports[1])]
            buckets.append(ofparser.OFPBucket(actions=actions))

            # send the group action
            req = ofparser.OFPGroupMod(datapath=datapath,
                                       type_=ofproto.OFPGT_ALL,
                                       group_id=i,
                                       buckets=buckets)
            datapath.send_msg(req)

            match = ofparser.OFPMatch(in_port=i, eth_type=0x8847)
            actions = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_gd_id=4,
                                                              operand_1_hf_id=0, operand_2_gd_id=out_ports[0]),
                       bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_gd_id=5,
                                                              operand_1_hf_id=0, operand_2_gd_id=out_ports[1]),
                       ofparser.OFPActionGroup(i)]
            self.add_flow(datapath=datapath, priority=600, table_id=0, match=match, actions=actions)

            # first packet of a flow
            match = ofparser.OFPMatch(state=0, in_port=i)
            actions = [bebaparser.OFPExpActionSetState(table_id=0, state=1, idle_timeout=2),
                       # saves timestamp
                       bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=4,
                                                              operand_1_hf_id=1, operand_2_cost=PROBE_FREQ)]
            insts = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                     ofparser.OFPInstructionGotoTable(1)]
            mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0, priority=500, match=match, instructions=insts)
            datapath.send_msg(mod)

            # simple forwarding packets go to second table to forward
            match = ofparser.OFPMatch(state=1, in_port=i, condition0=1)
            actions = [  # calculates deltaT: FDV[1]=HF[1]-FDV[0]=TS_NOW - TS_LAST
                bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUB, output_fd_id=1,
                                                       operand_1_hf_id=1, operand_2_fd_id=0),
                # calculates rate: R = (bytes / deltaT_ms) * 8 [kb/s]
                bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_MUL, output_fd_id=2,
                                                       operand_1_fd_id=2, operand_2_cost=8),
                # stores the result in FDV[3]: THE FLOW ESTIMATED RATE
                bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_DIV, output_fd_id=2,
                                                       operand_1_fd_id=2, operand_2_fd_id=1),
                # calculates ewma
                bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_EWMA, output_fd_id=3,
                                                       operand_1_fd_id=3, operand_2_cost=ALPHA,
                                                       operand_3_fd_id=2),
                # saves current timestamp
                bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=0,
                                                       operand_1_hf_id=1, operand_2_cost=0),
                # saves timestamp + probe freq
                bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_fd_id=4,
                                                       operand_1_hf_id=1, operand_2_cost=PROBE_FREQ),
                # reset byte counter
                bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUB, output_fd_id=2,
                                                       operand_1_fd_id=2, operand_2_fd_id=2),
                # saves in GDV[i] the ewma
                bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM, output_gd_id=i,
                                                       operand_1_fd_id=3, operand_2_cost=0)]
            instructions = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(1)]
            mod = ofparser.OFPFlowMod(datapath=datapath, priority=0, table_id=0, match=match, instructions=instructions)
            datapath.send_msg(mod)

            match = ofparser.OFPMatch(state=1, in_port=i, condition0=0)
            actions = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM,output_fd_id=2,
                                                              operand_1_fd_id=2, operand_2_hf_id=2)]
            instructions = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                            ofparser.OFPInstructionGotoTable(1)]
            mod = ofparser.OFPFlowMod(datapath=datapath, priority=0, table_id=0, match=match, instructions=instructions)
            datapath.send_msg(mod)

        ######################## TABLE 2: FORWARDING ################
        for i in LEAVES:
            match = ofparser.OFPMatch(eth_dst=MAC_ADDRS[i - 1])
            actions = [ofparser.OFPActionOutput(i)]
            self.add_flow(datapath=datapath, table_id=1, priority=0, match=match, actions=actions)

################### MONITORING

    def _monitor(self):
        plt.axis([0, 10, 0.5, 2.5])
        plt.yticks([1, 2])
        plt.axes().set_yticklabels(['path1', 'path2'])
        a = plt.scatter(0, 0, c='g', marker="^", s=100)
        c = plt.scatter(0, 0, c='r', s=100)
        plt.legend((a, c), ("h1 flow", "h3 flow"), loc='best', scatterpoints=1)
        plt.ion()

        for i in [0, 1, 2]:
            f = open(self.output_files[i], "w")
            f.write("Initializing for stateful switch %d\n" % (i+1))
            f.close()
        while True:
            self.time += 1
            for dp in self.datapaths:
                req = bebaparser.OFPExpStateStatsMultipartRequest(datapath=dp, table_id=3)
                dp.send_msg(req)
            hub.sleep(REQ_FREQ)

    @set_ev_cls(ofp_event.EventOFPExperimenterStatsReply, MAIN_DISPATCHER)
    def _state_stats_reply_handler(self, ev):
        msg = ev.msg
        dp_id = msg.datapath.id
        state_dict = {}

        if msg.body.experimenter == 0XBEBABEBA:
            if msg.body.exp_type == bebaproto.OFPMP_EXP_STATE_STATS:
                data = msg.body.data
                state_stats_list = bebaparser.OFPStateStats.parser(data, 0)
                if state_stats_list != 0:
                    for stat in state_stats_list:
                        if stat.entry.key:
                            state_dict[str(stat.entry.key)] = str(stat.entry.state)
                    if state_dict:
                        f = open(self.output_files[dp_id-1], 'a')
                        index = 1
                        first_key = []
                        for key in state_dict.keys():
                            f.write("time = " + str(self.time) + ",\t" + str(index) + ":\t" + state_dict[key] + ",\t")
                            index += 1
                            first_key = key
                        if dp_id == 3:
                            plt.axis([self.time-10, 10+self.time, 0.5, 2.5])
                            plt.scatter(self.time, int(state_dict[first_key]), c='r', s=100)
                        elif dp_id == 1:
                            plt.axis([self.time-10, 10+self.time, 0.5, 2.5])
                            plt.scatter(self.time, int(state_dict[first_key]), c='g', marker="^", s=100)

                        plt.draw()
                        f.write("\n")
                        f.close()
                else:
                    LOG.info("No data")
