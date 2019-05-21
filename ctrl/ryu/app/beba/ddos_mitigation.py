import pdb
import logging
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as osp
import ryu.ofproto.beba_v1_0_parser as osparser

# Import ryu library which is used for periodical call of 
# monitoring thread
from ryu.lib import hub

# Import helping library for packet parsing
from ryu.lib.packet import ethernet,packet,ipv4,tcp

# IP address helping library
import ipaddr, hashlib, threading


LOG = logging.getLogger('app.openstate.ddosmitigation')
################################################################################
################################################################################
class FlowStat:
    """
    This class is used for basic counting of new flows. This class is possible
    to use in the dictionary as a key because this object is hashable.
    """
    
    def __init__(self,dip,cnt):
        """
        This function is used for inicialization of the object

        Parameters:
            - dip   = destination IP address (string) 
            - cnt   =  value of the counter
        """
        # Initialize object with variables
        self.dip = ipaddr.IPv4Address(dip)
        
        # Setup the flow count
        self.cnt = cnt

        # Control variable which instructs the object to sum all the values
        # All data are incremented 
        self.last_value = 0
        self.value = cnt

    def __hash__(self):
        """
        Hashing function of FlowCnt. This function computes has from the 
        source/destination IP address, source/destination tcp port
        """
        # Get the integer representation of IP address
        return hash(self.dip)
        

    def __eq__(self,b):
        """
        Overloading of "=" operator.
    
        Parameters:
            - b - second object to compare

        Return:
            True if equal, false otherwise
        """
        # Check ip address
        if self.dip != b.dip:
            return False

        # They are equal
        return True


    def update(self,new):
        """
        Perform the update of the counter. Respect the last get_diff value.

        Parameters:
            - new - FlowStat object which is used for update
        """
        # Compute the diff and update the last value
        diff = new.cnt - self.last_value
        self.last_value = new.cnt
        # Increment the actual value with diff
        self.value = self.value + diff

    def get_diff(self):
        """
        Return the increment of the value since last get_diff call
        """
        retval = self.value
        self.value = 0
        return retval

################################################################################
################################################################################

class FSM_T0_Normal:
    """
    Table 0 FSM for normal mode of operation.
    """

    """
    FSM state definitions.
    """
    INIT = 0
    OPEN = 14 # TODO: Put all constanst to one class or package

    def load_fsm(self, datapath):
        LOG.info("Loading Table 0 normal FSM ...")
        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state INIT - ANY
        """
        Match a first packet of a new TCP flow (regardless of TCP flags)
        """
        match = ofparser.OFPMatch(eth_type=0x0800,
                ip_proto = 6,
                state = self.INIT)
        """
        Forward the packet to the corresponding output interface and create
        entries for both directions of given flow in the OPEN state (forward
        all consecutive packets).

        ( TODO - hard-coded output)
        """
        actions = [ofparser.OFPActionOutput(2),
                # Create entry for direction of incoming packet
                osparser.OFPExpActionSetState(state = self.OPEN,
                        table_id = 0,
                        # TODO - TIMEOUTS
                        idle_timeout = 10,
                        bit = 0),
                # Create entry for opposite direction since response is expected
                osparser.OFPExpActionSetState(state = self.OPEN,
                        table_id = 0,
                        # TODO - TIMEOUTS
                        idle_timeout = 10,
                        bit = 1)]
        """
        Apply forward actions and the creation of entries, pass the first packet
        to the table1 for the new TCP connections statistics computation.
        """
        inst = [ofparser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
                ofparser.OFPInstructionGotoTable(table_id = 1)]
        mod = ofparser.OFPFlowMod(datapath = datapath,
                table_id = 0,
                priority=100,
                match = match,
                instructions = inst)
        datapath.send_msg(mod)


        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state OPEN - ANY
        """
        Forward all consecutive packets of already seen flow by matching on
        previously created entries.
        """
        match = ofparser.OFPMatch(eth_type = 0x0800,
                ip_proto = 6,
                state = self.OPEN)
        """
        Just output packet to the corresponding output interface.

        ( TODO - hard-coded output)
        """
        actions = [ofparser.OFPActionOutput(2),
                ofparser.OFPActionOutput(1),
                # Refresh timeouts only
                osparser.OFPExpActionSetState(state = self.OPEN,
                        table_id = 0,
                        # TODO - TIMEOUTS
                        idle_timeout = 10,
                        bit = 0),
                # Refresh timeouts only
                osparser.OFPExpActionSetState(state = self.OPEN,
                        table_id = 0,
                        # TODO - TIMEOUTS
                        idle_timeout = 10,
                        bit = 1)]
        inst = [ofparser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(datapath = datapath,
                table_id = 0,
                priority = 100,
                match = match,
                instructions = inst)
        datapath.send_msg(mod)
        LOG.info("Done.")

################################################################################

class FSM_T0_Mtg:
    """
    Table 0 FSM for DDoS mitigation mode of operation.
    """

    """
    FSM state definitions.
    """
    # Special value, used when state of given entry will not be set.
    CH_STATE_NONE = -1

    INIT = 0
    SYN = 11
    SYN_ACK = 12
    ACK = 13
    OPEN = 14
    ERROR = 16
    """TODO limit retransmission count by parameter"""
    SYN_R = 111
    SYN_ACK_R = 121

    """
    TCP flag values
    """
    # Special value for ignoring packet's flags.
    F_DONT_CARE = 0xfff
    F_SYN = 0x02
    F_SYN_ACK = 0x12
    F_ACK = 0x10

    # Special value for dropping a packet.
    NO_OUTPUT = []
    # Values for packet counting determination..
    COUNT_PKT = True
    DO_NOT_COUNT_PKT = False


    """
    Template for packet handling rules.

    An incoming packet has to be an ethernet, TCP packet. The packet is matched
    to an entry in state "act_state" and optionally has to have "flags" set.
    Set "flags" to "self.F_DONT_CARE" to skip packet's flags matching.
    ( TODO - add masks?)

    Actions could be set to:
      - Output the packet to "output_ports" - list of output port
      numbers. Set parameter "output_ports" to "self.NO_OUTPUT" for dropping the
      packet.
      - Set a state and timeouts for the source (actual direction) and the
      destination (opposite direction) entries. Set "ch_state_src" /
      "ch_state_dst" to "self.CH_STATE_NONE" for skipping given direction entry.

    Instructions consists of an application of actions and an optional passage
    of the packet to the table1 for counting of first packets of new TCP
    connections. Set "count_in" to "self.COUNT_PKT" to pass the packet for
    counting, set to "self.DO_NOT_COUNT_PKT" otherwise.

    Finally a modification message with the "priority" from the parameter is
    composed and sent to the "datapath".
    """
    def process_packet(self, datapath,
            act_state, flags,
            output_ports,
            ch_state_src, idle_to_src, hard_to_src,
            ch_state_dst, idle_to_dst, hard_to_dst,
            priority,
            count_in):

        """
        Match packet - ethernet, TCP protocol, state (parameter), optional
        flags (parameter).
        """
        if flags == self.F_DONT_CARE:
            match = ofparser.OFPMatch(eth_type = 0x0800,
                    ip_proto = 6,
                    state = act_state)
        else:
            match = ofparser.OFPMatch(eth_type = 0x0800,
                    ip_proto = 6,
                    state = act_state,
                    tcp_flags = flags)

        """
        Set actions:
          - Output ports (parameter - list).
          - SetState for both directions (parameters).
        """
        actions = []
        for port in output_ports:
            actions.append(ofparser.OFPActionOutput(port))

        if ch_state_src != self.CH_STATE_NONE:
            actions.append(osparser.OFPExpActionSetState(state = ch_state_src,
                        table_id = 0,
                        # TODO - TIMEOUTS
                        idle_timeout = idle_to_src,
                        hard_timeout = hard_to_src,
                        bit = 0))

        if ch_state_dst != self.CH_STATE_NONE:
            actions.append(osparser.OFPExpActionSetState(state = ch_state_dst,
                        table_id = 0,
                        # TODO - TIMEOUTS
                        idle_timeout = idle_to_dst,
                        hard_timeout = hard_to_dst,
                        bit = 1))


        """
        Set instructions:
          - Apply previously defined actions.
          - Optionally pass packet to table1 for counting.
        """
        inst = [ofparser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,actions)]
        if count_in:
                inst.append(ofparser.OFPInstructionGotoTable(table_id=1))

        """
        Prepare and send message.
        """
        mod = ofparser.OFPFlowMod(datapath = datapath,
                table_id = 0,
                priority = priority,
                match = match,
                instructions = inst)
        datapath.send_msg(mod)


    def load_fsm(self, datapath):
        LOG.info("Loading Table 0 DDoS detection and mitigation FSM ...")
        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state ERROR - ANY
        """
        Any TCP packet received in ERROR state is dropped.
        """
        self.process_packet(datapath,
            self.ERROR, self.F_DONT_CARE,
            self.NO_OUTPUT,
            self.CH_STATE_NONE, 0, 0, # TODO - adjust timeouts
            self.CH_STATE_NONE, 0, 0, # TODO - adjust timeouts
            100,
            self.DO_NOT_COUNT_PKT) # TODO - count erroneous packets as they can be part of active DDoS?


        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state INIT - OK (SYN)
        """
        - Match first packet of new TCP flow - only SYN packet is allowed.
        - Drop first SYN packet (force a SYN packet retransmission).
        - Create an entry for the first SYN packet retransmission.
        - Pass this first packet to the table1 for a new TCP connections
          statistics computation.
        """
        self.process_packet(datapath,
            self.INIT, self.F_SYN,
            self.NO_OUTPUT,
            self.SYN, 10, 0, # TODO - adjust timeouts
            self.CH_STATE_NONE, 0, 0, # TODO - adjust timeouts
            100,
            self.COUNT_PKT)

        ## --------------------------
        ## state INIT - BAD (not SYN)
        """
        Every first TCP packet of new TCP connection, with flags different then
        SYN is considered as malicious.
        - Drop the packet.
        - Create new entry for this flow in erroneous state with hard-timeout

        ( TODO set hard or inactive timeout: blocking of active malicious flows
          vs. blocking valid attempts after initial failure if these attempts
          occurs more often then inactive timeout.)
        """
        self.process_packet(datapath,
            self.INIT, self.F_DONT_CARE,
            self.NO_OUTPUT,
            self.ERROR, 0, 10, # TODO - adjust timeouts
            self.CH_STATE_NONE, 0, 0, # TODO - adjust timeouts
            90,
            self.COUNT_PKT)


        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state SYN - OK (SYN - "forced" retransmission)
        """
        - Match a retransmitted SYN packet (which was intentionally dropped
          in the INIT state).
        - Forward the packet to the corresponding output interface.
        - Update an entry in source direction to the SYN_R state (for normal SYN
          retransmissions)
        - Create an entry for opposite direction in the SYN_ACK state (as the
          SYN+ACK packet is expected as a response to the SYN packet).

        ( TODO - hard-coded output)
        """
        self.process_packet(datapath,
            self.SYN, self.F_SYN,
            [2],
            self.SYN_R, 10, 0, # TODO - adjust timeouts
            self.SYN_ACK, 10, 0, # TODO - adjust timeouts
            100,
            self.DO_NOT_COUNT_PKT)

        ## --------------------------
        ## state SYN - BAD (not SYN)
        """
        Did not received retransmitted SYN packet (which was intentionally
        dropped in INIT state).
        - Drop the packet.
        - Transfer state of given entry into the ERROR state.
        """
        self.process_packet(datapath,
            self.SYN, self.F_DONT_CARE,
            self.NO_OUTPUT,
            self.ERROR, 0, 10, # TODO - adjust timeouts
            self.CH_STATE_NONE, 0, 0, # TODO - adjust timeouts
            90,
            self.DO_NOT_COUNT_PKT)


        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## state SYN_R - OK (SYN - "normal" retransmission)
        """
        - Match retransmitted SYN packet (normal retransmissions).
        - Forward a packet to the corresponding output interface.
        - Keep entry in the SYN_R state (source direction).

        - TODO Keep entry in the SYN_ACK state (opposite direction).

        ( TODO - limit retransmissions)
        ( TODO - hard-coded output)
        """
        self.process_packet(datapath,
            self.SYN_R, self.F_SYN,
            [2],
            self.SYN_R, 10, 0, # TODO - adjust timeouts
            # TODO - need to set this? refresh timeout?
            self.SYN_ACK, 10, 0, # TODO - adjust timeouts
            100,
            self.DO_NOT_COUNT_PKT)

        ## --------------------------
        ## SYN_R - BAD (not SYN)
        """
        Received unexpected TCP packet (expected only SYN retransmissions).
        - Drop the packet.
        - Transfer state of given entries (both directions) into the ERROR
          state.
        """
        self.process_packet(datapath,
            self.SYN_R, self.F_DONT_CARE,
            self.NO_OUTPUT,
            self.ERROR, 0, 10, # TODO - adjust timeouts
            self.ERROR, 0, 10, # TODO - adjust timeouts
            90,
            self.DO_NOT_COUNT_PKT)


        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## SYN_ACK - OK (SYN+ACK)
        """
        - Match a SYN+ACK packet (as a response to the SYN packet).
        - Forward the packet to the corresponding output interface.
        - Transfer a state to the SYN_ACK_R state for this direction (accept
          only SYN_ACK retransmissions).
        - Transfer a state to the ACK state for the opposite direction entry
          (a continuation of TCP handshake).

        ( TODO - hard-coded output)
        """
        self.process_packet(datapath,
            self.SYN_ACK, self.F_SYN_ACK,
            [1],
            self.SYN_ACK_R, 10, 0, # TODO - adjust timeouts
            self.ACK, 10, 0, # TODO - adjust timeouts
            100,
            self.DO_NOT_COUNT_PKT)

        ## --------------------------
        ## SYN_ACK - BAD (not SYN+ACK)
        """
        Received an unexpected TCP packet (expected only SYN+ACK).
        - Drop the packet.
        - Transfer state of given entries (both directions) into the ERROR
          state.
        """
        self.process_packet(datapath,
            self.SYN_ACK, self.F_DONT_CARE,
            self.NO_OUTPUT,
            self.ERROR, 0, 10, # TODO - adjust timeouts
            self.ERROR, 0, 10, # TODO - adjust timeouts
            90,
            self.DO_NOT_COUNT_PKT)


        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## SYN_ACK_R - OK (SYN+ACK - "normal" retransmission)
        """
        - Match retransmitted SYN+ACK packet(s).
        - Forward the packet to the corresponding output interface.
        - Transfer a state to the SYN_ACK_R state for this direction (accept
          only SYN_ACK retransmissions).
        - Transfer a state to the ACK state for an opposite direction entry
          (continuation of TCP handshake).

        ( TODO - hard-coded output)
        ( TODO - limit retransmissions)
        """
        self.process_packet(datapath,
            self.SYN_ACK_R, self.F_SYN_ACK,
            [1],
            self.SYN_ACK_R, 10, 0, # TODO - adjust timeouts
            # TODO - need to set this? refresh timeout?
            self.ACK, 10, 0, # TODO - adjust timeouts
            100,
            self.DO_NOT_COUNT_PKT)

        ## --------------------------
        ## SYN_ACK_R - BAD (not SYN_ACK)
        """
        Received an unexpected TCP packet (expected only SYN+ACK
        retransmissions).
        - Drop the packet.
        - Transfer a state of given entries (both directions) into the ERROR
          state.
        """
        self.process_packet(datapath,
            self.SYN_ACK_R, self.F_DONT_CARE,
            self.NO_OUTPUT,
            self.ERROR, 0, 10, # TODO - adjust timeouts
            self.ERROR, 0, 10, # TODO - adjust timeouts
            90,
            self.DO_NOT_COUNT_PKT)


        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## ACK - OK (ACK)
        """
        - Match an ACK packet (as a response to the SYN+ACK packet).
        - Forward the packet to the corresponding output interface.
        - Transfer states to the OPEN state for both directions.

        ( TODO - hard-coded output)
        """
        self.process_packet(datapath,
            self.ACK, self.F_ACK,
            [2],
            self.OPEN, 0, 0, # TODO - adjust timeouts
            self.OPEN, 0, 0, # TODO - adjust timeouts
            100,
            self.DO_NOT_COUNT_PKT)

        ## --------------------------
        ## ACK - BAD (not ACK)
        """
        Received an unexpected TCP packet (expected only an ACK packet).
        - Drop the packet.
        - Transfer state of given entries (both directions) into the ERROR
          state.
        """
        self.process_packet(datapath,
            self.SYN_ACK, self.F_DONT_CARE,
            self.NO_OUTPUT,
            self.ERROR, 0, 10, # TODO - adjust timeouts
            self.ERROR, 0, 10, # TODO - adjust timeouts
            90,
            self.DO_NOT_COUNT_PKT)


        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## OPEN - OK (ANY)
        """
        - Match any TCP packet.
        - Forward the packet to the corresponding output interface.
        - Keep entries for both directions in the OPEN state.

        ( TODO - hard-coded output)
        """
        self.process_packet(datapath,
            self.OPEN, self.F_DONT_CARE,
            [1,2],
            self.OPEN, 0, 0, # TODO - adjust timeouts
            self.OPEN, 0, 0, # TODO - adjust timeouts
            100,
            self.DO_NOT_COUNT_PKT)

        LOG.info("Done.")

        """
        TODO - keep track of FIN packets in the OPEN state, clear the record
        after a valid TCP connection termination.
        """

################################################################################

class FSM_T1_Cntr:
    """
    Table 1 FSM for counting of new TCP connections.
    """

    """
    FSM state definition.
    """
    INIT = 0
    ACTIVE = 1

    def load_fsm(self, datapath):
        LOG.info("Loading Table 1 FSM ...")
        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## INIT - ANY
        """
        Match firstly incoming packets.
       
        The actual version is little bit hacked, all incomming flows
        are forwarded to the table 2 which is performed counting of all incomming data.         

        (TODO - remove eth_type and ip_proto?)
        """
        match = ofparser.OFPMatch(eth_type = 0x0800,
                ip_proto = 6,
                state = self.INIT)

        actions = [osparser.OFPExpActionSetState(state = self.ACTIVE,
                table_id = 1,
                # TODO - TIMEOUTS
                idle_timeout = 1)]
        #inst = [ofparser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        inst = [ofparser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
                ofparser.OFPInstructionGotoTable(table_id = 2)]
        mod = ofparser.OFPFlowMod(datapath = datapath,
                table_id = 1,
                priority = 1,
                match = match,
                instructions = inst)
        datapath.send_msg(mod)

        ##=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#=#
        ## ACTIVE - ANY
        """
        Match other incoming packets. Need this state since we do not want to
        refresh timeouts of flow entry.

        (TODO - remove eth_type and ip_proto?)
        """
        match = ofparser.OFPMatch(eth_type = 0x0800,
                ip_proto = 6,
                state = self.ACTIVE)

        """
        TODO - simplify ... remove useless stuff
        """
        actions = []
        #inst = [ofparser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        inst = [ofparser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
                ofparser.OFPInstructionGotoTable(table_id = 2)]
        mod = ofparser.OFPFlowMod(datapath = datapath,
                table_id = 1,
                priority = 1,
                match = match,
                instructions = inst)
        datapath.send_msg(mod)

        LOG.info("Done.")


################################################################################
################################################################################
################################################################################

class OSDdosMitigation(app_manager.RyuApp):

    ##################################################
    # Declaration of control constants ###############
    ##################################################
    # Number of seconds to sleep
    MONITORING_SLEEP_TIME = 5

    # Number of new tcp connections (DDoS active)
    DDOS_ACTIVE_TRESHOLD = 100

    # Number of new tcp connections (DDoS not active)
    DDOS_INACTIVE_TRESHOLD = 50

    ##################################################
    # Implementation of methods        ###############
    ##################################################
    def __init__(self, *args, **kwargs):
        super(OSDdosMitigation, self).__init__(*args, **kwargs)
        self.normal_FSM=FSM_T0_Normal()
        self.ddos_mtg_FSM=FSM_T0_Mtg()
        self.counter_FSM=FSM_T1_Cntr()
        # Dictionary of FlowStat objects - actual set
        self.flows = {}
        # Flag, mitigation is on
        self.mitig_on = False

    def remove_table_flows(self, datapath, table_id, match, instructions):
        """
        Create OFP flow mod message to remove flows from table.
        """
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath,
                0,
                0,
                table_id,
                ofproto.OFPFC_DELETE,
                0,
                0,
                1,
                ofproto.OFPCML_NO_BUFFER,
                ofproto.OFPP_ANY,
                ofproto.OFPG_ANY,
                0,
                match,
                instructions)
        return flow_mod

    def add_flow(self, datapath, table_id, priority, match, actions):
        """
        Add flow to the BEBA switch
    
        Parameters:
            - datapath  = datapath to use
            - table_id  = table_id to use
            - priority  = priority of the rule, the rule with highest priority is selected
            - match     = structure for description of match rules
            - actions   = list of required actions 
        """
        if len(actions) > 0:
            inst = [ofparser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []
        mod = ofparser.OFPFlowMod(datapath = datapath,
                table_id = table_id,
                priority = priority,
                match = match,
                instructions = inst)
        datapath.send_msg(mod)


    def clear_table(self,datapath,table_id):
        """
        Cleans all table values

        Parameters:
            - datapath  = datapath to use
            - table_id  = id of the table
        """
        empty_match = ofparser.OFPMatch()
        instructions = []
        flow_mod = self.remove_table_flows(datapath,
                table_id,
                empty_match,
                instructions)
        datapath.send_msg(flow_mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event):
        """
        Switch sent his features, check if BEBA is supported.
        """
        # Parse the datapath and remmber it as class variable
        msg = event.msg
        self.datapath = msg.datapath

        ########################################################################
        ## Remove all entries from table 0,1 and 2
        self.clear_table(self.datapath,0) 
        self.clear_table(self.datapath,1) 
        self.clear_table(self.datapath,2)
 
        ########################################################################
        ## Table 0 (main table)
        LOG.info("Configuring switch %d..." % self.datapath.id)
        LOG.info("Setting up Table 0 ...")
        # Set table 0 as stateful
        req = osparser.OFPExpMsgConfigureStatefulTable(datapath = self.datapath,
                table_id = 0,
                stateful = 1)
        self.datapath.send_msg(req)
        
        # Set lookup extractor = {ip_src, ip_dst, tcp_src, tcp_dst} TODO - proto=TCP??
        req = osparser.OFPExpMsgKeyExtract(datapath = self.datapath,
                command = osp.OFPSC_EXP_SET_L_EXTRACTOR,
                fields = [ofp.OXM_OF_IPV4_SRC, ofp.OXM_OF_IPV4_DST, ofp.OXM_OF_TCP_SRC, ofp.OXM_OF_TCP_DST],
                table_id = 0)
        self.datapath.send_msg(req)
        
        # Set update extractor = {ip_src, ip_dst, tcp_src, tcp_dst}
        req = osparser.OFPExpMsgKeyExtract(datapath = self.datapath,
                command = osp.OFPSC_EXP_SET_U_EXTRACTOR,
                fields = [ofp.OXM_OF_IPV4_SRC, ofp.OXM_OF_IPV4_DST, ofp.OXM_OF_TCP_SRC, ofp.OXM_OF_TCP_DST],
                table_id = 0,
                bit = 0)
        self.datapath.send_msg(req)
        
        req = osparser.OFPExpMsgKeyExtract(datapath = self.datapath,
                command = osp.OFPSC_EXP_SET_U_EXTRACTOR,
                fields=[ofp.OXM_OF_IPV4_DST, ofp.OXM_OF_IPV4_SRC, ofp.OXM_OF_TCP_DST, ofp.OXM_OF_TCP_SRC],
                table_id = 0,
                bit = 1)
        self.datapath.send_msg(req)
        
        LOG.info("Done.")

        ########################################################################
        ## Table 1 (new TCP connection counter table)
        LOG.info("Setting up Table 1 ...")
        #  Set table 1 as stateful
        req = osparser.OFPExpMsgConfigureStatefulTable(datapath = self.datapath, table_id = 1, stateful = 1)
        self.datapath.send_msg(req)

        # Set lookup extractor = {ip_dst}
        # use dst IP + dst Port???
        req = osparser.OFPExpMsgKeyExtract(datapath = self.datapath,
                command = osp.OFPSC_EXP_SET_L_EXTRACTOR,
                fields = [ofp.OXM_OF_IPV4_DST],
                table_id = 1)
        self.datapath.send_msg(req)

        # Set update extractor = {ip_dst}
        req = osparser.OFPExpMsgKeyExtract(datapath = self.datapath,
                command = osp.OFPSC_EXP_SET_U_EXTRACTOR,
                fields = [ofp.OXM_OF_IPV4_DST],
                table_id = 1)
        self.datapath.send_msg(req)
        
        req = osparser.OFPExpMsgKeyExtract(datapath = self.datapath,
                command = osp.OFPSC_EXP_SET_U_EXTRACTOR,
                fields = [ofp.OXM_OF_IPV4_DST],
                table_id = 1,
                bit = 1)
        self.datapath.send_msg(req)
    
        # Little hack, prepare table 2 to be used for counting, the table 2 contains default rule which
        # is used for sending of all unknown packets to the controller.
        match = ofparser.OFPMatch(eth_type = 0x0800,ip_proto=6)
        actions = [ofparser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        inst = [ofparser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(datapath=self.datapath, table_id=2,priority=0, match=match, instructions=inst)
        self.datapath.send_msg(mod)

        LOG.info("Done.")

        ###################################################################################################
        ## Set switches behavior - start default behavior and afterthat start the monitoring thread
        ## Enable "ping" command
        self.load_arp_icmp()       

        ## Load FSM (table0) for normal mode of operation
        self.normal_FSM.load_fsm(self.datapath)

        ## Load FSM (table1) for counting of new tcp connections
        self.counter_FSM.load_fsm(self.datapath)
        
        ## Create a monitoring thread (each X seconds starst the statististics collection)
        self.monitor_thread = hub.spawn(self._monitor)
 
        LOG.info("Starting DDoS detection ...")

    def load_arp_icmp(self):
        """
        Enable ARP and ICMP protocol
        """
        match = ofparser.OFPMatch(eth_type = 0x0806)
        actions = [ofparser.OFPActionOutput(ofp.OFPP_FLOOD)]
        self.add_flow(datapath = self.datapath,
                table_id = 0,
                priority = 100,
                match = match,
                actions = actions)
        
        # ICMP packets flooding - simple, TEMPORARY and dull solution.
        match = ofparser.OFPMatch(eth_type = 0x0800,
                ip_proto = 1)
        actions = [ofparser.OFPActionOutput(ofp.OFPP_FLOOD)]
        self.add_flow(datapath = self.datapath,
                table_id = 0,
                priority = 1,
                match = match,
                actions=actions)

    def _ddos_detected(self,flow_cnt):
        """
        This is the helping function which is used for mathing
        of ddos treshold.

        Parameters:
            - flow_cnt      = number of new flwos

        Return: True if ddos treshold has been detected
        """
        if flow_cnt >= self.DDOS_ACTIVE_TRESHOLD:
            return True

        return False

    def _ddos_finished(self,flow_cnt):
        """
        This is the helping function which is used for mathing
        of ddos treshold.

        Parameters:
            - flow_cnt      = number of new flwos

        Return: True if ddos treshold has been finished
        """
        if flow_cnt <= self.DDOS_INACTIVE_TRESHOLD:
            return True

        return False

    def _monitor(self):
        """
        This is the monitoring thread which periodically 
        """
        # This function is used for a periodical start of the get statistics request
        cookie = cookie_mask = 0
        table_id = 2
        req = ofparser.OFPFlowStatsRequest(self.datapath, 0, table_id ,ofp.OFPP_ANY, ofp.OFPG_ANY,cookie, cookie_mask)
        while True:
            # Send request and wait for X seconds
            self.datapath.send_msg(req)
            hub.sleep(self.MONITORING_SLEEP_TIME) 
        
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        Handler for detection of  
        """
        # OFPFlowStats instantes will be transformed to FlowStat objecsts
        # and inserted to the list 
        new_flows = {}
        for stat in ev.msg.body:
            # Create a list of FlowStat objects (per destination)
            # Check if ipv4_dst is available in the match (default rule doesn't contain it)
            if not("ipv4_dst" in stat.match):
                continue

            # Parse data from stat ...
            dip = stat.match["ipv4_dst"]
            cnt = int(stat.packet_count) 
            tmp = FlowStat(dip,cnt)
             
            # Look for the object in the existing dictionary
            if tmp in self.flows:
                # Object is in the dictionary, perform the update of old object
                old_obj = self.flows[tmp]
                old_obj.update(tmp)
                tmp = old_obj
          
            # Store the FlowStat object to the dictionary
            new_flows[tmp] = tmp
                        
        # Setup new flow set and start the DDoS detection ...
        self.flows = new_flows 
        self.detect_ddos()            

    def detect_ddos(self):
        # Here, traverse through the list of all flows and compute the number of new flows
        new_flow_cnt = 0
        for v in self.flows.itervalues():
            # v = value in the dictionary
            diff = v.get_diff()
            new_flow_cnt = new_flow_cnt + diff
            
            debug_str = "    Number of new flows to ipv4_dst=%s is %d" %(str(v.dip),diff)
            LOG.info(debug_str)

        LOG.info("New flow count is %d" % (new_flow_cnt))
        
        if self._ddos_detected(new_flow_cnt) and self.mitig_on == False:
        ## Load FSM (table0) for DDoS mitigation mode of operation
            #self.clear_table(self.datapath,0)
            self.ddos_mtg_FSM.load_fsm(self.datapath)       
            self.load_arp_icmp()
            self.mitig_on = True
            LOG.info("Mitigation FSM has been loaded to Table 0")
        elif self._ddos_finished(new_flow_cnt) and self.mitig_on == True:
        ## Load FSM (table0) for normal mode of operation
            #self.clear_table(self.datapath,0)
            self.normal_FSM.load_fsm(self.datapath)
            self.load_arp_icmp()
            self.mitig_on = False
            LOG.info("Normal FSM has been loaded to Table 0")
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Handler for messages which are send from the controller (table2).
        This handler creates a rule in the flow table (table 2).

        Parameters:
            - ev    = mesage from the controller
        """
        # Parse data from message
        msg = ev.msg
        datapath = msg.datapath
        orig_match = msg.match       
        
        if not("ipv4_dst" in orig_match):
            LOG.info("No IPv4 destination IP has been detected.")
    
        dst_ipv4 = orig_match["ipv4_dst"]   
     
        # So far so good, create a new record in the flow table
        # TOOO: TIMEOUTS
        match = ofparser.OFPMatch(eth_type=0x0800,ipv4_dst=dst_ipv4,ip_proto=6)
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=2,priority=1, match=match)
        datapath.send_msg(mod)

        debug_str = "Counting rule for the flow (dst_ip=%s) has been created" % (dst_ipv4)
        LOG.info(debug_str)

## END OF DDoS Detection and Mitigation
