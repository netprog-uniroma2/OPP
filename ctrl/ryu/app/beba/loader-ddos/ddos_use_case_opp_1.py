import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.lib import hub
import math

LOG = logging.getLogger('app.openstate.evolution')

topo_scheme = """
                          s1              
                          | 
            3   1         |3        1   3
    h1 ----- sw1 ------- sw2 ------- sw3 ----- h3
              | 2       1   2       2 |
            3 | 2                   1 | 3
      s4 --- sw8                     sw4 --- s3
              | 1                   2 |
            2 |         2   1       1 | 3
    h2 ----- sw7 ------- sw6 ------- sw5 ----- h4
            3   1         |3        2   
                          |
                          s2\n"""

# switches' ids
STATELESS_SWITCHES = [4, 6, 8]
EDGE = [1, 3, 5, 7]
CORE = [2, 4, 6, 8]
STATEFUL_SWITCHES = [2]

SAMPLING_TIME = 100  # milliseconds
MULTIPLY_FACTOR = math.ceil((1000.0/SAMPLING_TIME)*4.5)  # multiplication factor for EWMA normalization
MONITORING_TIMEOUT = 0.1

IDLE = 0
MAX_PPS = 50

CORE_PORTS = [1, 2]
HOST_PORT = 3
addrs = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4']

REQ_FREQ = 0.5

server_dict = {2: '10.0.0.1', 4: '10.0.0.3', 6: '10.0.0.2', 8: '10.0.0.4'}

MAX_32 = pow(2, 32) - 1


class DDosDistributedDetection(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(DDosDistributedDetection, self).__init__(*args, **kwargs)
        self.datapaths = []
        self.output_file = "state1.txt"
        self.monitor_thread = hub.spawn(self._monitor)

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
        """ Switch sent his features, check if BEBA supported """
        msg = event.msg
        datapath = msg.datapath

        LOG.info("Configuring switch %d..." % datapath.id)

        if datapath.id in STATEFUL_SWITCHES:
            self.install_stateful(datapath)
            self.datapaths.append(datapath)
        elif datapath.id in STATELESS_SWITCHES:
            self.install_stateless(datapath)
        else:
            self.install_edges(datapath)

    ###################################### Install Functions #########################################

    def install_stateful(self, datapath):

        # configure stateful stage
        req = bebaparser.OFPExpMsgConfigureStatefulTable(
            datapath=datapath,
            table_id=0,
            stateful=1)
        datapath.send_msg(req)

        """ Set lookup extractor = {ip_dst} """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IPV4_DST],
                                             table_id=0)
        datapath.send_msg(req)

        """ Set update extractor = {ip_dst} (same as lookup) """
        req = bebaparser.OFPExpMsgKeyExtract(datapath=datapath,
                                             command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR,
                                             fields=[ofproto.OXM_OF_IPV4_DST],
                                             table_id=0)
        datapath.send_msg(req)

        # sampling time
        req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
            datapath=datapath,
            table_id=0,
            global_data_variable_id=1,
            value=SAMPLING_TIME)
        datapath.send_msg(req)

        # Threshold
        req = bebaparser.OFPExpMsgsSetGlobalDataVariable(
            datapath=datapath,
            table_id=0,
            global_data_variable_id=0,
            value=MAX_PPS)
        datapath.send_msg(req)

        # threshold exceeding condition
        req = bebaparser.OFPExpMsgSetCondition(
            datapath=datapath,
            condition=bebaproto.CONDITION_GTE,
            condition_id=1,
            table_id=0,
            operand_1_fd_id=3,
            operand_2_gd_id=0)
        datapath.send_msg(req)

        # time condition
        req = bebaparser.OFPExpMsgSetCondition(
            datapath=datapath,
            condition=bebaproto.CONDITION_GTE,
            condition_id=0,
            table_id=0,
            operand_1_hf_id=1,
            operand_2_fd_id=1)
        datapath.send_msg(req)

        # threshold exceeding condition
        req = bebaparser.OFPExpMsgSetCondition(
            datapath=datapath,
            condition=bebaproto.CONDITION_GTE,
            condition_id=2,
            table_id=0,
            operand_1_fd_id=2,
            operand_2_gd_id=0)
        datapath.send_msg(req)

        # timestamp extractor
        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=0,
            extractor_id=1,
            field=bebaproto.OXM_EXP_TIMESTAMP)
        datapath.send_msg(req)

        # metadata extractor
        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=0,
            extractor_id=0,
            field=ofproto.OXM_OF_METADATA)
        datapath.send_msg(req)

        # timestamp extractor
        req = bebaparser.OFPExpMsgHeaderFieldExtract(
            datapath=datapath,
            table_id=0,
            extractor_id=2,
            field=bebaproto.OXM_EXP_PKT_LEN)
        datapath.send_msg(req)

        ############################### TAB 0: STATEFUL ############################################
        """ For each state entry
            FDV[0]: count
            FDV[1]: delta timestamp
            FDV[2]: ewma representing switch's own state
            FDV[3]: global state
        """

        match = ofparser.OFPMatch(eth_type=0x800, in_port=HOST_PORT)
        self.add_flow(datapath=datapath, priority=200, table_id=0, match=match, actions=[])

        # common instructions
        instGoto1 = [ofparser.OFPInstructionGotoTable(1)]

        # packet counter ++
        actionUpdateCounter = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM,
                                                                      output_fd_id=0, operand_1_fd_id=0,
                                                                      operand_2_cost=1)]
        # reset counter to 0
        actionResetCounter = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUB,
                                                                     output_fd_id=0, operand_1_fd_id=0,
                                                                     operand_2_fd_id=0)]
        # save timestamp+1second
        actionSaveTimestamp = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_SUM,
                                                                      output_fd_id=1, operand_1_hf_id=1,
                                                                      operand_2_gd_id=1)]

        # Calculates EWMA on packet number
        actionEvaluateEWMA = [bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_MUL,
                                                                     output_fd_id=0, operand_1_fd_id=0,
                                                                     operand_2_cost=MULTIPLY_FACTOR),
                              bebaparser.OFPExpActionSetDataVariable(table_id=0, opcode=bebaproto.OPCODE_EWMA,
                                                                     output_fd_id=2, operand_1_fd_id=2,
                                                                     operand_2_cost=bebaproto.EWMA_PARAM_0875,
                                                                     operand_3_fd_id=0)]

        actionSetDSCPAttack = [ofparser.OFPActionSetField(ip_dscp=26)]
        actionSetDSCPNormal = [ofparser.OFPActionSetField(ip_dscp=13)]

        """ Measures and state transitions """

        """ #T1_R1 """
        """ First packet of a flow """
        match = ofparser.OFPMatch(state=0, eth_type=0x800)
        actions = [bebaparser.OFPExpActionSetState(state=1, table_id=0, idle_timeout=MONITORING_TIMEOUT)] + \
                  actionUpdateCounter + actionSaveTimestamp + actionSetDSCPNormal
        insts = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] + instGoto1
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0, priority=50, match=match, instructions=insts)
        datapath.send_msg(mod)

        """ #T1_R2 """
        """ State is MONITORING; in between the window
            ACTIONS: counter++ and set NORMAL DSCP info"""
        match = ofparser.OFPMatch(state=1, condition0=0, eth_type=0x800)
        actions = actionUpdateCounter + actionSetDSCPNormal
        insts = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] + instGoto1
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0, priority=15, match=match, instructions=insts)
        datapath.send_msg(mod)

        """ #T1_R3 """
        """ State is MONITORING; sampling time expired
            ACTIONS: evaluate EWMA, counter = 0, save new timestamp+SAMPLING"""
        match = ofparser.OFPMatch(state=1, condition0=1, eth_type=0x800)
        actions = actionEvaluateEWMA + actionResetCounter + actionSaveTimestamp
        insts = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] + instGoto1
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0, priority=20, match=match, instructions=insts)
        datapath.send_msg(mod)

        """ #T1_R4 """
        """ State is in MONITORING, the switch's own state is over threshold now
            ACTIONS: go to ATTACK state and trigger the control message """
        match = ofparser.OFPMatch(state=1, condition2=1, eth_type=0x800)
        # apply mitigation policy
        actions = [bebaparser.OFPExpActionSetState(state=2, table_id=0)] + actionSetDSCPAttack
        insts = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] + instGoto1
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0, priority=30, match=match, instructions=insts)
        datapath.send_msg(mod)

        """ #T1_R6 """
        """ State is ATTACK, no more over threshold, either the sum of states or switch's own state"""
        match = ofparser.OFPMatch(state=2, condition2=0, eth_type=0x800)
        actions = [bebaparser.OFPExpActionSetState(state=1, table_id=0, idle_timeout=MONITORING_TIMEOUT)] +\
                  actionSetDSCPNormal
        insts = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] + instGoto1
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0, priority=100, match=match, instructions=insts)
        datapath.send_msg(mod)

        """ #T1_R7 """
        """ State is ATTACK, monitor condition is valid"""
        match = ofparser.OFPMatch(state=2, condition0=0, eth_type=0x800)
        actions = actionUpdateCounter + actionSetDSCPAttack
        insts = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] + instGoto1
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0, priority=50, match=match, instructions=insts)
        datapath.send_msg(mod)

        """ #T1_R8 """
        """ State is ATTACK, window expired """
        match = ofparser.OFPMatch(state=2, condition0=1, eth_type=0x800)
        actions = actionEvaluateEWMA + actionResetCounter + actionSaveTimestamp + actionSetDSCPAttack
        insts = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)] + instGoto1
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0, priority=50, match=match, instructions=insts)
        datapath.send_msg(mod)

        ########################    TAB 1: STATELESS    ########################################
        """ #T2_R3 """
        # Pkts destined to host attached to switch
        match = ofparser.OFPMatch(eth_type=0x800, ipv4_dst=server_dict[datapath.id])
        actions = [ofparser.OFPActionOutput(HOST_PORT)]
        self.add_flow(datapath=datapath, table_id=1, priority=70, match=match, actions=actions)

        # SW 2
        """ #T2_R4-5 """
        match = ofparser.OFPMatch(in_port=1, eth_type=0x800, ipv4_dst=addrs[3])
        actions = [ofparser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
        self.add_flow(datapath=datapath, table_id=1, priority=50, match=match, actions=actions)

        match = ofparser.OFPMatch(in_port=2, eth_type=0x800, ipv4_dst=addrs[2])
        actions = [ofparser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
        self.add_flow(datapath=datapath, table_id=1, priority=50, match=match, actions=actions)

        match = ofparser.OFPMatch(in_port=2, eth_type=0x800, ipv4_dst=addrs[3])
        actions = [ofparser.OFPActionOutput(1)]
        self.add_flow(datapath=datapath, table_id=1, priority=50, match=match, actions=actions)

        match = ofparser.OFPMatch(in_port=1, eth_type=0x800, ipv4_dst=addrs[2])
        actions = [ofparser.OFPActionOutput(2)]
        self.add_flow(datapath=datapath, table_id=1, priority=50, match=match, actions=actions)

        match = ofparser.OFPMatch(in_port=1, eth_type=0x800, ipv4_dst=addrs[1])
        actions = [ofparser.OFPActionOutput(2)]
        self.add_flow(datapath=datapath, table_id=1, priority=50, match=match, actions=actions)

        match = ofparser.OFPMatch(in_port=2, eth_type=0x800, ipv4_dst=addrs[1])
        actions = [ofparser.OFPActionOutput(1)]
        self.add_flow(datapath=datapath, table_id=1, priority=50, match=match, actions=actions)

    # Stateless switches
    def install_stateless(self, datapath):
        ################################ TAB 0: FWD ###################################
        match = ofparser.OFPMatch(eth_type=0x800, in_port=HOST_PORT)
        self.add_flow(datapath=datapath, priority=0, table_id=0, match=match, actions=[])

        match = ofparser.OFPMatch(eth_type=0x800, ip_dscp=0)
        actions = [ofparser.OFPActionOutput(1 if datapath.id != 8 else 2)]
        self.add_flow(datapath=datapath, priority=100, table_id=0, match=match, actions=actions)

        # If: sw[i] is connected to the host -> deliver the packet 
        match = ofparser.OFPMatch(eth_type=0x800, ipv4_dst=server_dict[datapath.id])
        actions = [ofparser.OFPActionOutput(HOST_PORT)]
        self.add_flow(datapath=datapath, priority=10, table_id=0, match=match, actions=actions)

        # Else: forward it to the other ports
        for p in CORE_PORTS:
            # If ip_dst does not belong to the host directly connected to me,
            #   drop the packet because it is already been forwarded
            match = ofparser.OFPMatch(in_port=p, eth_type=0x800)
            actions = [ofparser.OFPActionOutput(1 if p == 2 else 2)]
            self.add_flow(datapath=datapath, priority=0, table_id=0, match=match, actions=actions)

    # Edge stateless switches
    def install_edges(self, datapath):
        # Static routes configuration
        if datapath.id == 7:
            match = ofparser.OFPMatch(in_port=HOST_PORT)
            actions = [ofparser.OFPActionOutput(2)]
            self.add_flow(datapath=datapath, priority=0, table_id=0, match=match, actions=actions)
        else:
            match = ofparser.OFPMatch(in_port=HOST_PORT)
            actions = [ofparser.OFPActionOutput(1)]
            self.add_flow(datapath=datapath, priority=0, table_id=0, match=match, actions=actions)

        # Dumbly forward ALL
        for p in CORE_PORTS:
            match = ofparser.OFPMatch(in_port=p)
            actions = [ofparser.OFPActionOutput(1 if p == 2 else 2)]
            self.add_flow(datapath=datapath, priority=5, table_id=0, match=match, actions=actions)


################### MONITORING

    def _monitor(self):
        f = open(self.output_file, "w")
        f.write("Initializing for stateful switch 1\n")
        f.close()
        while True:
            for dp in self.datapaths:
                req = bebaparser.OFPExpStateStatsMultipartRequest(datapath=dp, table_id=0)
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
                            state_dict[str(stat.entry.key)] = str(stat.entry.flow_data_var[2]) + ",\t" +\
                                                              str(stat.entry.flow_data_var[3])
                    if state_dict:
                        f = open(self.output_file, 'a')
                        for key in state_dict.keys():
                            f.write(key + ": " + state_dict[key] + "\t")
                        f.write("\n")
                        f.close()
                else:
                    LOG.info("No data")
