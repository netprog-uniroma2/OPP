# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser
from ryu.lib import hub
from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo
from mininet.node import UserSwitch,RemoteController
import os,subprocess,time,sys
from ryu.ofproto.ofproto_common import BEBA_EXPERIMENTER_ID
import struct

class BebaErrorExperimenterMsg(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(BebaErrorExperimenterMsg, self).__init__(*args, **kwargs)
        if os.geteuid() != 0:
            exit("You need to have root privileges to run this script")
        # Kill Mininet
        os.system("sudo mn -c 2> /dev/null")
        print 'Starting Mininet'
        self.net = Mininet(topo=SingleSwitchTopo(7),switch=UserSwitch,controller=RemoteController,cleanup=True,autoSetMacs=True,listenPort=6634,autoStaticArp=True)
        self.net.start()
        self.last_error_queue = []
        self.test_id = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.monitor_thread = hub.spawn(getattr(self, '_monitor%s' % self.test_id),datapath)
        self.test_id += 1

    def add_flow(self, datapath, priority, match, actions):

        inst = [ofparser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = ofparser.OFPFlowMod(
                datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=priority, buffer_id=ofproto.OFP_NO_BUFFER,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_table_mod(self, datapath):
        req = bebaparser.OFPExpMsgConfigureStatefulTable(datapath=datapath, table_id=0, stateful=1)
        datapath.send_msg(req)

    def send_key_lookup(self, datapath):
        key_lookup_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofproto.OXM_OF_ETH_SRC,ofproto.OXM_OF_ETH_DST], table_id=0)
        datapath.send_msg(key_lookup_extractor)

    def send_key_update(self, datapath):
        key_update_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofproto.OXM_OF_ETH_SRC,ofproto.OXM_OF_ETH_DST], table_id=0)
        datapath.send_msg(key_update_extractor)

    def test0(self,datapath):
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        

    def test1(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        actions = [ofparser.OFPActionOutput(2,0)]
        match = ofparser.OFPMatch(in_port=1,state=6)
        self.add_flow(datapath, 150, match, actions)

        actions = [bebaparser.OFPExpActionSetState(state=6,table_id=10)]
        match = ofparser.OFPMatch(in_port=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [ofparser.OFPActionOutput(1,0)]
        match = ofparser.OFPMatch(in_port=2)
        self.add_flow(datapath, 200, match, actions)

    def test2(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        actions = [ofparser.OFPActionOutput(2,0)]
        match = ofparser.OFPMatch(in_port=1,state=6)
        self.add_flow(datapath, 150, match, actions)

        actions = [bebaparser.OFPExpActionSetState(state=6,table_id=200)]
        match = ofparser.OFPMatch(in_port=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [ofparser.OFPActionOutput(1,0)]
        match = ofparser.OFPMatch(in_port=2)
        self.add_flow(datapath, 200, match, actions)

    def test3(self,datapath):
        self.send_table_mod(datapath)

        # I provide zero fields => I cannot set an empty extractor!
        key_lookup_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR, fields=[], table_id=0)
        datapath.send_msg(key_lookup_extractor)
        # I provide more fields than allowed
        key_lookup_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofproto.OXM_OF_ETH_SRC,ofproto.OXM_OF_ETH_DST,ofproto.OXM_OF_IPV4_DST,ofproto.OXM_OF_TCP_SRC,ofproto.OXM_OF_TCP_DST,ofproto.OXM_OF_UDP_SRC,ofproto.OXM_OF_UDP_DST], table_id=0)
        datapath.send_msg(key_lookup_extractor)

    def test4(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        # I provide zero keys => I cannot access the state table with an empty key!
        state = bebaparser.OFPExpMsgSetFlowState(datapath=datapath, state=88, keys=[], table_id=0)
        datapath.send_msg(state)
        # I provide more keys than allowed
        state = bebaparser.OFPExpMsgSetFlowState(datapath=datapath, state=88, keys=[0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,2,0,0,0,0,0,4,5], table_id=0)
        datapath.send_msg(state)

    def test5(self,datapath):
        self.send_table_mod(datapath)
        key_lookup_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofproto.OXM_OF_ETH_SRC], table_id=0)
        datapath.send_msg(key_lookup_extractor)
        key_update_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofproto.OXM_OF_ETH_SRC], table_id=0)
        datapath.send_msg(key_update_extractor)
        state = bebaparser.OFPExpMsgSetFlowState(datapath=datapath, state=88, keys=[10,0,0,5], table_id=0)
        datapath.send_msg(state)

    def test6(self,datapath):
        self.send_table_mod(datapath)
        key_lookup_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofproto.OXM_OF_ETH_SRC], table_id=0)
        datapath.send_msg(key_lookup_extractor)
        key_update_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofproto.OXM_OF_ETH_SRC], table_id=0)
        datapath.send_msg(key_update_extractor)
        state = bebaparser.OFPExpMsgDelFlowState(datapath=datapath, keys=[10,0,0,5], table_id=0)
        datapath.send_msg(state)

    def test7(self,datapath):
        self.send_table_mod(datapath)
        key_lookup_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofproto.OXM_OF_ETH_SRC,ofproto.OXM_OF_ETH_DST], table_id=0)
        datapath.send_msg(key_lookup_extractor)
        key_update_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofproto.OXM_OF_ETH_SRC], table_id=0)
        datapath.send_msg(key_update_extractor)

    def test8(self,datapath):
        self.send_table_mod(datapath)
        key_update_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofproto.OXM_OF_ETH_SRC], table_id=0)
        datapath.send_msg(key_update_extractor)
        key_lookup_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofproto.OXM_OF_ETH_SRC,ofproto.OXM_OF_ETH_DST], table_id=0)
        datapath.send_msg(key_lookup_extractor)

    def test9(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        state = bebaparser.OFPExpMsgSetFlowState(datapath=datapath, state=88, keys=[0,0,0,0,0,2,0,0,0,0,0,4], table_id=200)
        datapath.send_msg(state)

    def test10(self,datapath):
        self.send_table_mod(datapath)
        actions = [ofparser.OFPActionOutput(6,0)]
        match = ofparser.OFPMatch(in_port=5,ip_proto=1,eth_type=0x800,global_state=2863311530)
        self.add_flow(datapath, 150, match, actions)

        msg = bebaparser.OFPExpSetGlobalState(datapath=datapath, global_state=2863311530, global_state_mask=0xffffffff)
        datapath.send_msg(msg)

        actions = [ofparser.OFPActionOutput(5,0)]
        match = ofparser.OFPMatch(in_port=6,ip_proto=1,eth_type=0x800)
        self.add_flow(datapath, 150, match, actions)

    def test11(self,datapath):
        self.send_table_mod(datapath)
        (global_state, global_state_mask) = bebaparser.masked_global_state_from_str("1*1*1*1*1*1*1*1*0*0*1*1*1*1*1*1*")
        actions = [ofparser.OFPActionOutput(6,0)]
        match = ofparser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1,global_state=bebaparser.masked_global_state_from_str("1*1*1*1*1*1*1*1*0*0*1*1*1*1*1*1*"))
        self.add_flow(datapath, 150, match, actions)

        msg = bebaparser.OFPExpSetGlobalState(datapath=datapath, global_state=global_state, global_state_mask=global_state_mask)
        datapath.send_msg(msg)

        actions = [ofparser.OFPActionOutput(5,0)]
        match = ofparser.OFPMatch(in_port=6,ip_proto=1,eth_type=0x800)
        self.add_flow(datapath, 200, match, actions)

    def test12(self,datapath):
        self.send_table_mod(datapath)
        actions = [ofparser.OFPActionOutput(6,0)]
        match = ofparser.OFPMatch(in_port=5,ip_proto=1,eth_type=0x800,global_state=1492)
        self.add_flow(datapath, 200, match, actions)

        actions = [bebaparser.OFPExpActionSetGlobalState(global_state=1492)]
        match = ofparser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [ofparser.OFPActionOutput(5,0)]
        match = ofparser.OFPMatch(in_port=6,eth_type=0x800,ip_proto=1)
        self.add_flow(datapath, 200, match, actions)

    def test13(self,datapath):
        self.send_table_mod(datapath)
        (global_state, global_state_mask) = bebaparser.masked_global_state_from_str("*1*1*1*1*0*0*1*1*1*1*1*1*")
        actions = [ofparser.OFPActionOutput(6,0)]
        match = ofparser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1,global_state=bebaparser.masked_global_state_from_str("*1*1*1*1*0*0*1*1*1*1*1*1*"))
        self.add_flow(datapath, 200, match, actions)

        actions = [bebaparser.OFPExpActionSetGlobalState(global_state=global_state, global_state_mask=global_state_mask)]
        match = ofparser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [ofparser.OFPActionOutput(5,0)]
        match = ofparser.OFPMatch(in_port=6,eth_type=0x800,ip_proto=1)
        self.add_flow(datapath, 200, match, actions)

    def test14(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)

        command=255
        data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command)
        exp_type=bebaproto.OFPT_EXP_STATE_MOD
        msg = ofparser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)
        datapath.send_msg(msg)

    def test15(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)

        # dummy data payload
        command=255
        data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command)

        exp_type=2**32-1
        msg = ofparser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)
        datapath.send_msg(msg)

    def test16(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)

        command=bebaproto.OFPSC_EXP_SET_FLOW_STATE
        # instead of packing into '!Bx'
        data=struct.pack('!B', command)
        exp_type=bebaproto.OFPT_EXP_STATE_MOD
        msg = ofparser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)
        datapath.send_msg(msg)

    def test17(self,datapath):
        state = bebaparser.OFPExpMsgSetFlowState(datapath=datapath, state=88, keys=[0,0,0,0,0,2,0,0,0,0,0,4], table_id=0)
        datapath.send_msg(state)

    def test18(self,datapath):
        state = bebaparser.OFPExpMsgDelFlowState(datapath=datapath, keys=[0,0,0,0,0,2,0,0,0,0,0,4], table_id=0)
        datapath.send_msg(state)

    def test19(self,datapath):
        data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, bebaproto.OFPSC_EXP_SET_GLOBAL_STATE)
    
        exp_type=bebaproto.OFPT_EXP_STATE_MOD
        msg = ofparser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)
        datapath.send_msg(msg)

    def test20(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        act_type=10
        data=struct.pack('!I4xB',act_type,0)
        a = ofparser.OFPActionExperimenterUnknown(experimenter=0XBEBABEBA, data=data)
        actions = [a]
        match = ofparser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1)
        self.add_flow(datapath, 100, match, actions)

    def test21(self,datapath):
        command=bebaproto.OFPSC_EXP_STATEFUL_TABLE_CONFIG
        data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command)
        data+=struct.pack('!B',0)
    
        exp_type=bebaproto.OFPT_EXP_STATE_MOD
        msg = ofparser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)
        datapath.send_msg(msg)

    def test22(self,datapath):
        command=bebaproto.OFPSC_EXP_STATEFUL_TABLE_CONFIG
        data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command)
        data+=struct.pack(bebaproto.OFP_EXP_STATE_MOD_STATEFUL_TABLE_CONFIG_PACK_STR,250,1)
    
        exp_type=bebaproto.OFPT_EXP_STATE_MOD
        msg = ofparser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)
        datapath.send_msg(msg)

    def test23(self,datapath):
        self.send_table_mod(datapath)
        key_lookup_extractor = bebaparser.OFPExpMsgKeyExtract(datapath=datapath, command=bebaproto.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofproto.OXM_OF_ETH_SRC], table_id=250)
        datapath.send_msg(key_lookup_extractor)

    def test24(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        state = bebaparser.OFPExpMsgDelFlowState(datapath=datapath, keys=[0,0,0,0,0,2,0,0,0,0,0,4], table_id=0)
        datapath.send_msg(state)

    def test25(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        state = bebaparser.OFPExpMsgDelFlowState(datapath=datapath, keys=[0,0,0,0,0,2,0,0,0,0,0,4], table_id=250)
        datapath.send_msg(state)

    def test26(self,datapath):
        command=bebaproto.OFPSC_EXP_DEL_FLOW_STATE
        data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command)
        data+=struct.pack('!B3xIBBBB',0,3,0,0,0,1)
        
        exp_type=bebaproto.OFPT_EXP_STATE_MOD
        msg = ofparser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)
        datapath.send_msg(msg)

    def test27(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        state = bebaparser.OFPExpMsgDelFlowState(datapath=datapath, keys=[0,0,0,0,0,2,0,0,0,0,0,4,0], table_id=0)
        datapath.send_msg(state)

    def test28(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        act_type=bebaproto.OFPAT_EXP_SET_STATE
        data=struct.pack('!I4xB',act_type,0)
        a = ofparser.OFPActionExperimenterUnknown(experimenter=0XBEBABEBA, data=data)
        actions = [a]
        match = ofparser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1)
        self.add_flow(datapath, 100, match, actions)

    def test29(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        act_type=bebaproto.OFPAT_EXP_SET_GLOBAL_STATE
        data=struct.pack('!I4x',act_type)
        a = ofparser.OFPActionExperimenterUnknown(experimenter=0XBEBABEBA, data=data)
        actions = [a]
        match = ofparser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1)
        self.add_flow(datapath, 100, match, actions)

    def test30(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        actions = []
        match = ofparser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1)
        i = bebaparser.OFPInstructionInSwitchPktGen(0, actions)
        i.instr_type = 56
        inst = [i]
        mod = ofparser.OFPFlowMod(datapath=datapath, table_id=0,
                                priority=100, match=match, instructions=inst)
        datapath.send_msg(mod)

    def test31(self,datapath):
        from scapy.all import Ether, ARP
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        pkt_data = str(Ether(src='00:01:02:03:04:05', dst='46:9c:96:30:ff:d5')/ARP(
                        hwsrc='00:01:02:03:04:05',hwdst='46:9c:96:30:ff:d5',psrc="172.16.0.2",pdst='172.16.0.1',op=2))
        command=50
        data=struct.pack(bebaproto.OFP_EXP_PKTTMP_MOD_PACK_STR, command)
        data+=struct.pack(bebaproto.OFP_EXP_PKTTMP_MOD_ADD_PKTTMP_PACK_STR, 0)
        data+=pkt_data
        exp_type=bebaproto.OFPT_EXP_PKTTMP_MOD
        req =ofparser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)
        datapath.send_msg(req)
    
    def test32(self,datapath):
        from scapy.all import Ether, ARP
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        exp_type=bebaproto.OFPT_EXP_PKTTMP_MOD
        data=struct.pack('!B',bebaproto.OFPSC_ADD_PKTTMP)
        req =ofparser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)
        datapath.send_msg(req)

    def test33(self,datapath):
        from scapy.all import Ether, ARP
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        pkt_data = str(Ether(src='00:01:02:03:04:05', dst='46:9c:96:30:ff:d5')/ARP(
                        hwsrc='00:01:02:03:04:05',hwdst='46:9c:96:30:ff:d5',psrc="172.16.0.2",pdst='172.16.0.1',op=2))
        command=bebaproto.OFPSC_ADD_PKTTMP
        data=struct.pack(bebaproto.OFP_EXP_PKTTMP_MOD_PACK_STR, command)
        exp_type=bebaproto.OFPT_EXP_PKTTMP_MOD
        req =ofparser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)
        datapath.send_msg(req)

    def test34(self,datapath):
        from scapy.all import Ether, ARP
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        pkt_data = str(Ether(src='00:01:02:03:04:05', dst='46:9c:96:30:ff:d5')/ARP(
                        hwsrc='00:01:02:03:04:05',hwdst='46:9c:96:30:ff:d5',psrc="172.16.0.2",pdst='172.16.0.1',op=2))
        command=bebaproto.OFPSC_DEL_PKTTMP
        data=struct.pack(bebaproto.OFP_EXP_PKTTMP_MOD_PACK_STR, command)
        exp_type=bebaproto.OFPT_EXP_PKTTMP_MOD
        req =ofparser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)
        datapath.send_msg(req)

    '''
    To perform test #35 you have to comment lines 129-130 of ryu/ofproto/oxx_fields.py file and recompile the controller.
    Furthermore you have to uncomment _monitor35 in this file
    With this little patch the controller does not mask the match field, triggering the error at switch side.
    
    def test35(self,datapath):
        self.send_table_mod(datapath)
        actions = []
        match = ofparser.OFPMatch(in_port=1,ip_proto=1,eth_type=0x800,state=(7,8))
        self.add_flow(datapath, 150, match, actions)
    '''


    def wait_for_error(self,test_num,err_type,err_code):
        attempts = 0
        while len(self.last_error_queue)!=1 and attempts<3:
            print 'Waiting %d seconds...' % (3-attempts)
            attempts += 1
            time.sleep(1)

        if len(self.last_error_queue)==1 and self.last_error_queue[0]==(err_type,err_code):
            print 'Test %d: \x1b[32mSUCCESS!\x1b[0m' % test_num
            self.last_error_queue = []
        else:
            print 'Test %d: \x1b[31mFAIL\x1b[0m' % test_num
            self.stop_test_and_exit()

    def wait_for_two_errors(self,test_num,err_type1,err_code1,err_type2,err_code2):
        attempts = 0
        while len(self.last_error_queue)!=2 and attempts<3:
            print 'Waiting %d seconds...' % (3-attempts)
            attempts += 1
            time.sleep(1)

        if len(self.last_error_queue)==2 and self.last_error_queue[0]==(err_type1,err_code1) and self.last_error_queue[1]==(err_type2,err_code2):
            print 'Test %d: \x1b[32mSUCCESS!\x1b[0m' % test_num
            self.last_error_queue = []
        else:
            print 'Test %d: \x1b[31mFAIL\x1b[0m' % test_num
            self.stop_test_and_exit()

    def try_ping(self,test_num,source,dest,drop_perc,wait=True):
        if wait:
            attempts = 0
            while len(self.last_error_queue)==0 and attempts<3:
                print 'Waiting %d seconds...' % (3-attempts)
                attempts += 1
                time.sleep(1)

        drop_perc = self.net.ping(hosts=[self.net.hosts[source],self.net.hosts[dest]],timeout=1)
        if len(self.last_error_queue)==0 and drop_perc == drop_perc:
            print 'Test %d: \x1b[32mSUCCESS!\x1b[0m' % test_num
        else:
            print 'Test %d: \x1b[31mFAIL\x1b[0m' % test_num
            self.stop_test_and_exit()

    def _monitor0(self,datapath):
        print("Network is ready")

        # [TEST 0] Setting the extractor on a stateless stage should be impossible
        self.test0(datapath)
        self.wait_for_two_errors(0,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_EXP_SET_EXTRACTOR,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_EXP_SET_EXTRACTOR)
        self.restart_mininet()

    def _monitor1(self,datapath):
        print("Network is ready")

        # [TEST 1] Set state action must be performed onto a stateful stage (run-time check => no error is returned!)
        # mininet> h1 ping -c5 h2
        # ping should fail, but rules are correctly installed
        self.test1(datapath)
        self.try_ping(test_num=1,source=0,dest=1,drop_perc=100)
        self.restart_mininet()

    def _monitor2(self,datapath):
        print("Network is ready")

        # [TEST 2] Set state action must be performed onto a stage with table_id less or equal than the number of pipeline's tables (install-time check)
        self.test2(datapath)
        self.wait_for_error(2,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_TABLE_ID)
        self.restart_mininet()
        
    def _monitor3(self,datapath):
        print("Network is ready")

        # [TEST 3]  OFPExpMsgKeyExtract: I should provide a number of fields >0 and <MAX_FIELD_COUNT
        self.test3(datapath)
        self.wait_for_two_errors(3,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor4(self,datapath):
        print("Network is ready")

        # [TEST 4] OFPExpMsgSetFlowState: I should provide a key of size >0 and <MAX_KEY_LEN
        self.test4(datapath)
        self.wait_for_two_errors(4,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor5(self,datapath):
        print("Network is ready")

        # [TEST 5] OFPExpMsgSetFlowState: I should provide a key of size consistent with the number of fields of the update-scope
        self.test5(datapath)
        self.wait_for_error(5,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor6(self,datapath):
        print("Network is ready")

        # [TEST 6] OFPExpMsgDelFlowState: I should provide a key of size consistent with the number of fields of the update-scope
        self.test6(datapath)
        self.wait_for_error(6,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor7(self,datapath):
        print("Network is ready")

        # [TEST 7] OFPExpMsgKeyExtract: lookup-scope and update-scope must provide same length keys
        self.test7(datapath)
        self.wait_for_error(7,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor8(self,datapath):
        print("Network is ready")

        # [TEST 8] OFPExpMsgKeyExtract: lookup-scope and update-scope must provide same length keys
        self.test8(datapath)
        self.wait_for_error(8,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor9(self,datapath):
        print("Network is ready")

        # [TEST 9] OFPExpMsgSetFlowState: must be executed onto a stage with table_id<=64 (number of pipeline's tables)
        self.test9(datapath)
        self.wait_for_error(9,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_TABLE_ID)
        self.restart_mininet()

    def _monitor10(self,datapath):
        print("Network is ready")

        # [TEST 10] exact match on global_state
        # mininet> h5 ping -c1 h6
        self.test10(datapath)
        self.try_ping(test_num=10,source=4,dest=5,drop_perc=0)
        self.restart_mininet()

    def _monitor11(self,datapath):
        print("Network is ready")

        # [TEST 11] masked match on global_state
        # mininet> h5 ping -c1 h6
        self.test11(datapath)
        self.try_ping(test_num=11,source=4,dest=5,drop_perc=0)
        self.restart_mininet()

    def _monitor12(self,datapath):
        print("Network is ready")

        # [TEST 12] exact match on global_state
        # mininet> h5 ping -c2 h6
        # the first ping should fail
        self.test12(datapath)
        # TODO: if Mininet had 'count' parameter we could simplify the code by checking drop_perc=0.25 with count=2
        self.try_ping(test_num=12,source=4,dest=5,drop_perc=50)
        self.try_ping(test_num=12,source=4,dest=5,drop_perc=0,wait=False)
        self.restart_mininet()

    def _monitor13(self,datapath):
        print("Network is ready")

        # [TEST 13] masked match on global_state
        # mininet> h5 ping -c5 h6
        # the first ping should fail
        self.test12(datapath)
        # TODO: if Mininet had 'count' parameter we could simplify the code by checking drop_perc=0.25 with count=2
        self.try_ping(test_num=13,source=4,dest=5,drop_perc=50)
        self.try_ping(test_num=13,source=4,dest=5,drop_perc=0,wait=False)
        self.restart_mininet()

    def _monitor14(self,datapath):
        print("Network is ready")

        # [TEST 14]_STATE MOD with unknown command
        self.test14(datapath)
        self.wait_for_error(14,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_EXP_STATE_MOD_BAD_COMMAND)
        self.restart_mininet()

    def _monitor15(self,datapath):
        print("Network is ready")

        # [TEST 15]_Beba unknown experimenter message
        self.test15(datapath)
        self.wait_for_error(15,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_MESSAGE)
        self.restart_mininet()

    def _monitor16(self,datapath):
        print("Network is ready")

        # [TEST 16]_STETE MOD experimenter message too short
        self.test16(datapath)
        self.wait_for_error(16,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor17(self,datapath):
        print("Network is ready")

        # [TEST 17]_Set_state in a non stateful stage
        self.test17(datapath)
        self.wait_for_error(17,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_EXP_SET_FLOW_STATE)
        self.restart_mininet()

    def _monitor18(self,datapath):
        print("Network is ready")

        # [TEST 18]_Del_flow_state in a non stateful stage
        self.test18(datapath)
        self.wait_for_error(18,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_EXP_DEL_FLOW_STATE)
        self.restart_mininet()

    def _monitor19(self,datapath):
        print("Network is ready")

        # [TEST 19]_setglobalstate with invalid length
        self.test19(datapath)
        self.wait_for_error(19,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()
    
    def _monitor20(self,datapath):
        print("Network is ready")

        # [TEST 20]_unknown Beba experimenter action
        self.test20(datapath)
        self.wait_for_error(20,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_ACTION)
        self.restart_mininet()

    def _monitor21(self,datapath):
        print("Network is ready")

        # [TEST 21]_State Mod Stateful table config with invalid length
        self.test21(datapath)
        self.wait_for_error(21,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor22(self,datapath):
        print("Network is ready")

        # [TEST 22]_State Mod Stateful table config with invalid table ID
        self.test22(datapath)
        self.wait_for_error(22,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_TABLE_ID)
        self.restart_mininet()

    def _monitor23(self,datapath):
        print("Network is ready")

        # [TEST 23]_Set extractor with invalid table ID
        self.test22(datapath)
        self.wait_for_error(23,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_TABLE_ID)
        self.restart_mininet()

    def _monitor24(self,datapath):
        print("Network is ready")

        # [TEST 24]_Del_flow_state with empty state table
        self.test24(datapath)
        self.wait_for_error(24,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_EXP_DEL_FLOW_STATE)
        self.restart_mininet()

    def _monitor25(self,datapath):
        print("Network is ready")

        # [TEST 25]_Del_flow_state with invalid table ID
        self.test25(datapath)
        self.wait_for_error(25,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_TABLE_ID)
        self.restart_mininet()

    def _monitor26(self,datapath):
        print("Network is ready")

        # [TEST 26]_Del_flow_state with bad length
        self.test26(datapath)
        self.wait_for_error(26,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor27(self,datapath):
        print("Network is ready")

        # [TEST 27]_Del_flow_state with key not consistent with update scope
        self.test27(datapath)
        self.wait_for_error(27,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor28(self,datapath):
        print("Network is ready")

        # [TEST 28] Set state action with invalid length
        self.test28(datapath)
        self.wait_for_error(28,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor29(self,datapath):
        print("Network is ready")

        # [TEST 29] Set global state action with invalid length
        self.test29(datapath)
        self.wait_for_error(29,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor30(self,datapath):
        print("Network is ready")

        # [TEST 30]_unknown Beba experimenter instruction
        self.test30(datapath)
        self.wait_for_error(30,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_INSTRUCTION)
        self.restart_mininet()

    def _monitor31(self,datapath):
        print("Network is ready")

        # [TEST 31]_PKTTMP MOD with unknown command
        self.test31(datapath)
        self.wait_for_error(31,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_EXP_PKTTMP_MOD_BAD_COMMAND)
        self.restart_mininet()

    def _monitor32(self,datapath):
        print("Network is ready")

        # [TEST 32]_PKTTMP MOD with too short
        self.test32(datapath)
        self.wait_for_error(32,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor33(self,datapath):
        print("Network is ready")

        # [TEST 33]_ADD_PKTTMP command too short
        self.test33(datapath)
        self.wait_for_error(33,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        self.restart_mininet()

    def _monitor34(self,datapath):
        print("Network is ready")

        # [TEST 34]_DEL_PKTTMP command too short
        self.test34(datapath)
        self.wait_for_error(34,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_EXP_LEN)
        #self.restart_mininet()
        self.stop_test_and_gracefully_exit()

    '''
    To perform the test #35 you have to comment lines 129-130 of ryu/ofproto/oxx_fields.py file and recompile the controller
    Furthermore you have to uncomment test35 in this file
    With this little patch the controller does not mask the match field, triggering the error at switch side.

    def _monitor35(self,datapath):
        print("Network is ready")

        # [TEST 35] Bad masked state match field
        self.test35(datapath)
        self.wait_for_error(35,ofproto.OFPET_EXPERIMENTER,bebaproto.OFPEC_BAD_MATCH_WILDCARD)
        #self.restart_mininet()
        self.stop_test_and_gracefully_exit()
    '''

    @set_ev_cls(ofp_event.EventOFPErrorExperimenterMsg,
                    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def exp_error_msg_handler(self, ev):
        msg = ev.msg
        if msg.experimenter == BEBA_EXPERIMENTER_ID:
            self.last_error_queue.append((msg.type,msg.exp_type))

    def stop_test_and_exit(self):
        # Kill Mininet and/or Ryu
        self.net.stop()
        os.system("sudo mn -c 2> /dev/null")
        os.system("kill -9 $(pidof -x ryu-manager) 2> /dev/null")

    def stop_test_and_gracefully_exit(self):
        # Kill Mininet and/or Ryu
        self.net.stop()
        os.system("sudo mn -c 2> /dev/null")
        # Send SIGTERM instead of SIGKILL
        os.system("kill -7 $(pidof -x ryu-manager) 2> /dev/null")

    def restart_mininet(self):
        print 'Restarting Mininet\n'
        os.system("sudo mn -c 2> /dev/null")
        self.net = Mininet(topo=SingleSwitchTopo(7),switch=UserSwitch,controller=RemoteController,cleanup=True,autoSetMacs=True,listenPort=6634,autoStaticArp=True)
        self.net.start()
