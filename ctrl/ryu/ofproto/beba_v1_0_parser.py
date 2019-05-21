import struct
from ryu.lib.pack_utils import msg_pack_into
from ryu.ofproto.ofproto_parser import StringifyMixin, MsgBase, msg_str_attr
import ryu.ofproto.ofproto_v1_3_parser as ofproto_parser
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.beba_v1_0 as bebaproto
from ryu import utils
import logging
import six
from array import array

LOG = logging.getLogger('ryu.ofproto.beba_v1_0_parser')

def OFPExpActionSetState(state, table_id, bit=0, hard_timeout=0, idle_timeout=0, hard_rollback=0, idle_rollback=0, state_mask=0xffffffff, fields=[]):
    """ 
    Returns a Set state experimenter action

    This action applies the state. TO DO: look how deal with ofl msg instruction
    and also cls
    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    state            State instance
    state_mask       State mask
    table_id         Stage ID
    bit              Enable/Disable swapping of the source/destination addresses a
                     and source/destination ports in the case of bi-flow identificatin
    ================ ======================================================
    """
    field_count=len(fields)

    if field_count > bebaproto.MAX_FIELD_COUNT:
        field_count = 0
        LOG.debug("OFPExpActionSetState: Number of fields given > MAX_FIELD_COUNT")

    act_type=bebaproto.OFPAT_EXP_SET_STATE
    data=struct.pack(bebaproto.OFP_EXP_ACTION_SET_STATE_PACK_STR, act_type, state, state_mask, table_id, hard_rollback, idle_rollback, hard_timeout*1000000, idle_timeout*1000000, bit, field_count)

    field_extract_format='!I'

    if field_count <= bebaproto.MAX_FIELD_COUNT:
        for f in range(field_count):
            data+=struct.pack(field_extract_format,fields[f])
    
    # Actions must be 64 bit aligned! Fields are 32bits, so we need padding only if field_count is odd
    if field_count>0 and field_count%2!=0:
        data+=struct.pack(field_extract_format,0)

    return ofproto_parser.OFPActionExperimenterUnknown(experimenter=0xBEBABEBA, data=data)

def OFPExpActionSetGlobalState(global_state, global_state_mask=0xffffffff):
    """ 
    Returns a Set Global State experimenter action

    This action updates the switch global state.
    
    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    global_state             Global state value
    global_state_mask        Mask value
    ================ ======================================================
    """
    act_type=bebaproto.OFPAT_EXP_SET_GLOBAL_STATE
    data=struct.pack(bebaproto.OFP_EXP_ACTION_SET_GLOBAL_STATE_PACK_STR, act_type, global_state, global_state_mask)
    return ofproto_parser.OFPActionExperimenterUnknown(experimenter=0XBEBABEBA, data=data)

def OFPExpActionIncState(table_id):
    """ 
    Returns a Set Inc state experimenter action

    This action increment the current state.
    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    table_id         Stage ID
    """
    act_type=bebaproto.OFPAT_EXP_INC_STATE
    data=struct.pack(bebaproto.OFP_EXP_ACTION_INC_STATE_PACK_STR, act_type, table_id)

    return ofproto_parser.OFPActionExperimenterUnknown(experimenter=0xBEBABEBA, data=data)

def OFPExpActionSetDataVariable(table_id, opcode, bit=0, output_gd_id=None, output_fd_id=None, operand_1_fd_id=None, operand_1_gd_id=None, operand_1_hf_id=None, operand_2_fd_id=None, operand_2_gd_id=None, operand_2_hf_id=None, operand_2_cost=None, operand_3_fd_id=None, operand_3_gd_id=None, operand_3_hf_id=None,operand_4_fd_id=None, operand_4_gd_id=None, operand_4_hf_id=None, coeff_1=0, coeff_2=0, coeff_3=0, coeff_4=0, fields=[]):
    """ 
    Returns a Set Data Variable experimenter action

    This action updates the flow data/global data variable.
    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    table_id         Stage ID
    opcode           Operation code
    output_XX_id     ID of destination global/data variable
    operand_1_XX_id  ID of first global/data variable/header field
    operand_2_XX_id  ID of second global/data variable/header field/constant
    operand_3_XX_id  ID of third global/data variable/header field
    operand_4_XX_id  ID of fourth global/data variable/header field
    bit              Enable/Disable swapping of the source/destination addresses a
                     and source/destination ports in the case of bi-flow identificatin
    ================ ======================================================
    """
    field_count=len(fields)

    if field_count > bebaproto.MAX_FIELD_COUNT:
        field_count = 0
        LOG.debug("OFPExpActionSetState: Number of fields given > MAX_FIELD_COUNT")

    act_type=bebaproto.OFPAT_EXP_SET_DATA_VAR

    if opcode>bebaproto.OPCODE_POLY_SUM:
        LOG.debug("OFPExpActionSetDataVariable: invalid opcode")

    if sum(1 for i in [output_gd_id,output_fd_id] if i != None)!=1:
        LOG.debug("OFPExpActionSetDataVariable: you need to choose exactly one type of output operand")

    if sum(1 for i in [operand_1_fd_id,operand_1_gd_id,operand_1_hf_id] if i != None)!=1:
        LOG.debug("OFPExpActionSetDataVariable: you need to choose exactly one type of first operand")

    if sum(1 for i in [operand_2_fd_id,operand_2_gd_id,operand_2_hf_id,operand_2_cost] if i != None)!=1:
        LOG.debug("OFPExpActionSetDataVariable: you need to choose exactly one type of second output operand")

    #TODO Davide: check for third/fourth operand (only some opcodes have more than 2)

    # operand_types=aabbccdde0000000 where aa=operand_1_type, bb=operand_2_type, cc=operand_3_type, dd=operand_4_type and e=output_type
    if operand_1_fd_id!=None:
        if operand_1_fd_id<0 or operand_1_fd_id>bebaproto.MAX_FLOW_DATA_VAR_NUM-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid flow data variable ID")
        operand_types=bebaproto.OPERAND_TYPE_FLOW_DATA_VAR<<14
        operand_1=operand_1_fd_id
    elif operand_1_gd_id!=None:
        if operand_1_gd_id<0 or operand_1_gd_id>bebaproto.MAX_GLOBAL_DATA_VAR_NUM-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid global data variable ID")
        operand_types=bebaproto.OPERAND_TYPE_GLOBAL_DATA_VAR<<14
        operand_1=operand_1_gd_id
    elif operand_1_hf_id!=None:
        if operand_1_hf_id<0 or operand_1_hf_id>bebaproto.MAX_HEADER_FIELDS-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid header field ID")
        operand_types=bebaproto.OPERAND_TYPE_HEADER_FIELD<<14
        operand_1=operand_1_hf_id

    if operand_2_fd_id!=None:
        if operand_2_fd_id<0 or operand_2_fd_id>bebaproto.MAX_FLOW_DATA_VAR_NUM-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid flow data variable ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_FLOW_DATA_VAR<<12
        operand_2=operand_2_fd_id
    elif operand_2_gd_id!=None:
        if operand_2_gd_id<0 or operand_2_gd_id>bebaproto.MAX_GLOBAL_DATA_VAR_NUM-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid global data variable ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_GLOBAL_DATA_VAR<<12
        operand_2=operand_2_gd_id
    elif operand_2_hf_id!=None:
        if operand_2_hf_id<0 or operand_2_hf_id>bebaproto.MAX_HEADER_FIELDS-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid header field ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_HEADER_FIELD<<12
        operand_2=operand_2_hf_id
    elif operand_2_cost!=None:
        if operand_2_cost<0 or operand_2_cost>255:
            LOG.debug("OFPExpActionSetDataVariable: constant is too big")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_CONSTANT<<12
        operand_2=operand_2_cost

    if operand_3_fd_id!=None:
        if operand_3_fd_id<0 or operand_3_fd_id>bebaproto.MAX_FLOW_DATA_VAR_NUM-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid flow data variable ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_FLOW_DATA_VAR<<10
        operand_3=operand_3_fd_id
    elif operand_3_gd_id!=None:
        if operand_3_gd_id<0 or operand_3_gd_id>bebaproto.MAX_GLOBAL_DATA_VAR_NUM-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid global data variable ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_GLOBAL_DATA_VAR<<10
        operand_3=operand_3_gd_id
    elif operand_3_hf_id!=None:
        if operand_3_hf_id<0 or operand_3_hf_id>bebaproto.MAX_HEADER_FIELDS-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid header field ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_HEADER_FIELD<<10
        operand_3=operand_3_hf_id
    else:
        operand_3 = 0

    if operand_4_fd_id!=None:
        if operand_4_fd_id<0 or operand_4_fd_id>bebaproto.MAX_FLOW_DATA_VAR_NUM-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid flow data variable ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_FLOW_DATA_VAR<<8
        operand_4=operand_4_fd_id
    elif operand_4_gd_id!=None:
        if operand_4_gd_id<0 or operand_4_gd_id>bebaproto.MAX_GLOBAL_DATA_VAR_NUM-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid global data variable ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_GLOBAL_DATA_VAR<<8
        operand_4=operand_4_gd_id
    elif operand_4_hf_id!=None:
        if operand_4_hf_id<0 or operand_4_hf_id>bebaproto.MAX_HEADER_FIELDS-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid header field ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_HEADER_FIELD<<8
        operand_4=operand_4_hf_id
    else:
        operand_4 = 0

    if coeff_1<-128 or coeff_1>127:
        LOG.debug("OFPExpActionSetDataVariable: requires -128 <= coeff_1 <= 127")
    if coeff_2<-128 or coeff_2>127:
        LOG.debug("OFPExpActionSetDataVariable: requires -128 <= coeff_2 <= 127")
    if coeff_3<-128 or coeff_3>127:
        LOG.debug("OFPExpActionSetDataVariable: requires -128 <= coeff_3 <= 127")
    if coeff_4<-128 or coeff_4>127:
        LOG.debug("OFPExpActionSetDataVariable: requires -128 <= coeff_4 <= 127")

    if output_fd_id!=None:
        if output_fd_id<0 or output_fd_id>bebaproto.MAX_FLOW_DATA_VAR_NUM-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid flow data variable ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_FLOW_DATA_VAR<<7
        output=output_fd_id
    elif output_gd_id!=None:
        if output_gd_id<0 or output_gd_id>bebaproto.MAX_GLOBAL_DATA_VAR_NUM-1:
            LOG.debug("OFPExpActionSetDataVariable: invalid global data variable ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_GLOBAL_DATA_VAR<<7
        output=output_gd_id

    if opcode==bebaproto.OPCODE_EWMA and ( operand_2_cost<0 or operand_2_cost>6 ):
        LOG.debug("OFPExpActionSetDataVariable, OPCODE_EWMA: requires 0 <= operand_2_cost <= 6")
    
    data=struct.pack(bebaproto.OFP_EXP_ACTION_SET_DATA_VARIABLE_PACK_STR, act_type, operand_types, table_id, opcode, output, operand_1, operand_2, operand_3, operand_4, coeff_1, coeff_2, coeff_3, coeff_4, field_count, bit)

    field_extract_format='!I'

    if field_count <= bebaproto.MAX_FIELD_COUNT:
        for f in range(field_count):
            data+=struct.pack(field_extract_format,fields[f])
    
    # Actions must be 64 bit aligned! Fields are 32bits, so we need padding only if field_count is odd
    if field_count>0 and field_count%2!=0:
        data+=struct.pack(field_extract_format,0)

    return ofproto_parser.OFPActionExperimenterUnknown(experimenter=0xBEBABEBA, data=data)

def OFPExpActionWriteContextToField(src_type,dst_field,src_id=None):
    """ 
    Returns a Write Context to Field experimenter action

    This action write data context informations into the packet header
    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    src_type         Source type
    src_type         Source ID
    dst_field        Destination field
    ================ ======================================================
    """
    act_type=bebaproto.OFPAT_EXP_WRITE_CONTEXT_TO_FIELD

    if src_type<bebaproto.SOURCE_TYPE_FLOW_DATA_VAR or src_type>bebaproto.SOURCE_TYPE_STATE:
        LOG.debug("OFPExpActionWriteContextToField: invalid src_type")

    if src_type in [bebaproto.SOURCE_TYPE_FLOW_DATA_VAR,bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR] and src_id==None:
        LOG.debug("OFPExpActionWriteContextToField: src_id cannot be None with \"flow_data_var\" or \"global_data_var\" type")

    if src_type==bebaproto.SOURCE_TYPE_FLOW_DATA_VAR:
        if src_id<0 or src_id>bebaproto.MAX_FLOW_DATA_VAR_NUM-1:
            LOG.debug("OFPExpActionWriteContextToField: invalid flow data variable ID")
    elif src_type==bebaproto.SOURCE_TYPE_GLOBAL_DATA_VAR:
        if src_id<0 or src_id>bebaproto.MAX_GLOBAL_DATA_VAR_NUM-1:
            LOG.debug("OFPExpActionWriteContextToField: invalid global data variable ID")
    elif src_type==bebaproto.SOURCE_TYPE_STATE:
        src_id=0

    data=struct.pack(bebaproto.OFP_EXP_WRITE_CONTEXT_TO_FIELD_PACK_STR, act_type, src_type, src_id, dst_field)
    return ofproto_parser.OFPActionExperimenterUnknown(experimenter=0xBEBABEBA, data=data)

def OFPExpActionDecapsulateGTP():

    act_type=bebaproto.OFPAT_EXP_DECAPSULATE_GTP

    data=struct.pack(bebaproto.OFP_EXP_DECAPSULATE_GTP_PACK_STR, act_type)
    return ofproto_parser.OFPActionExperimenterUnknown(experimenter=0xBEBABEBA, data=data)

def OFPExpActionSoftDecapsulateGTP():

    act_type=bebaproto.OFPAT_EXP_SOFT_DECAPSULATE_GTP

    data=struct.pack(bebaproto.OFP_EXP_SOFT_DECAPSULATE_GTP_PACK_STR, act_type)
    return ofproto_parser.OFPActionExperimenterUnknown(experimenter=0xBEBABEBA, data=data)

def OFPExpActionEncapsulateGTP(pkttmp_id):

    act_type=bebaproto.OFPAT_EXP_ENCAPSULATE_GTP

    data=struct.pack(bebaproto.OFP_EXP_ENCAPSULATE_GTP_PACK_STR, act_type, 0x0, pkttmp_id)
    return ofproto_parser.OFPActionExperimenterUnknown(experimenter=0xBEBABEBA, data=data)

def OFPExpMsgConfigureStatefulTable(datapath, stateful, table_id):
    command=bebaproto.OFPSC_EXP_STATEFUL_TABLE_CONFIG
    data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command)
    data+=struct.pack(bebaproto.OFP_EXP_STATE_MOD_STATEFUL_TABLE_CONFIG_PACK_STR,table_id,stateful)
    
    exp_type=bebaproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpMsgKeyExtract(datapath, command, fields, table_id, biflow=0, bit=0):
    field_count=len(fields)

    if field_count > bebaproto.MAX_FIELD_COUNT:
        field_count = 0
        LOG.debug("OFPExpMsgKeyExtract: Number of fields given > MAX_FIELD_COUNT")

    data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command) # msg type
    data+=struct.pack(bebaproto.OFP_EXP_STATE_MOD_EXTRACTOR_PACK_STR,table_id,biflow,bit,field_count)
    field_extract_format='!I'

    if field_count <= bebaproto.MAX_FIELD_COUNT:
        for f in range(field_count):
            data+=struct.pack(field_extract_format,fields[f])
    
    exp_type=bebaproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpMsgSetCondition(datapath, table_id, condition_id, condition, operand_1_fd_id=None, operand_1_gd_id=None, operand_1_hf_id=None, operand_2_fd_id=None, operand_2_gd_id=None, operand_2_hf_id=None):
    command=bebaproto.OFPSC_EXP_SET_CONDITION

    if condition_id<0 or condition_id>bebaproto.MAX_CONDITIONS_NUM-1:
        LOG.debug("OFPExpMsgSetCondition: invalid condition_id")

    if condition<0 or condition>5:
        LOG.debug("OFPExpMsgSetCondition: invalid condition")

    if sum(1 for i in [operand_1_fd_id,operand_1_gd_id,operand_1_hf_id] if i != None)!=1:
        LOG.debug("OFPExpMsgSetCondition: you need to choose exactly one type of operand_1")        

    if sum(1 for i in [operand_2_fd_id,operand_2_gd_id,operand_2_hf_id] if i != None)!=1:
        LOG.debug("OFPExpMsgSetCondition: you need to choose exactly one type of operand_2")

    # operand_types=xxyy0000 where xx=operand_1_type and yy=operand_2_type
    if operand_1_fd_id!=None:
        if operand_1_fd_id<0 or operand_1_fd_id>bebaproto.MAX_FLOW_DATA_VAR_NUM-1:
            LOG.debug("OFPExpMsgSetCondition: invalid flow data variable ID")
        operand_types=bebaproto.OPERAND_TYPE_FLOW_DATA_VAR<<6
        operand_1=operand_1_fd_id
    elif operand_1_gd_id!=None:
        if operand_1_gd_id<0 or operand_1_gd_id>bebaproto.MAX_GLOBAL_DATA_VAR_NUM-1:
            LOG.debug("OFPExpMsgSetCondition: invalid global data variable ID")
        operand_types=bebaproto.OPERAND_TYPE_GLOBAL_DATA_VAR<<6
        operand_1=operand_1_gd_id
    elif operand_1_hf_id!=None:
        if operand_1_hf_id<0 or operand_1_hf_id>bebaproto.MAX_HEADER_FIELDS-1:
            LOG.debug("OFPExpMsgSetCondition: invalid header field ID")
        operand_types=bebaproto.OPERAND_TYPE_HEADER_FIELD<<6
        operand_1=operand_1_hf_id

    if operand_2_fd_id!=None:
        if operand_2_fd_id<0 or operand_2_fd_id>bebaproto.MAX_FLOW_DATA_VAR_NUM-1:
            LOG.debug("OFPExpMsgSetCondition: invalid flow data variable ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_FLOW_DATA_VAR<<4
        operand_2=operand_2_fd_id
    elif operand_2_gd_id!=None:
        if operand_2_gd_id<0 or operand_2_gd_id>bebaproto.MAX_GLOBAL_DATA_VAR_NUM-1:
            LOG.debug("OFPExpMsgSetCondition: invalid global data variable ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_GLOBAL_DATA_VAR<<4
        operand_2=operand_2_gd_id
    elif operand_2_hf_id!=None:
        if operand_2_hf_id<0 or operand_2_hf_id>bebaproto.MAX_HEADER_FIELDS-1:
            LOG.debug("OFPExpMsgSetCondition: invalid header field ID")
        operand_types=operand_types | bebaproto.OPERAND_TYPE_HEADER_FIELD<<4
        operand_2=operand_2_hf_id    

    data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command)
    data+=struct.pack(bebaproto.OFP_EXP_STATE_MOD_SET_CONDITION_PACK_STR,table_id,condition_id,condition,operand_types,operand_1,operand_2)
    
    exp_type=bebaproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpMsgsSetGlobalDataVariable(datapath, table_id, global_data_variable_id, value, mask=0xffffffff):
    command=bebaproto.OFPSC_EXP_SET_GLOBAL_DATA_VAR

    if global_data_variable_id<0 or global_data_variable_id>bebaproto.MAX_GLOBAL_DATA_VAR_NUM-1:
        LOG.debug("OFPExpMsgsSetGlobalDataVariable: invalid global_data_variable_id")

    data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command)
    data+=struct.pack(bebaproto.OFP_EXP_STATE_MOD_SET_GLOBAL_DATA_VAR_PACK_STR,table_id,global_data_variable_id,value,mask)
    
    exp_type=bebaproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpMsgSetFlowDataVariable(datapath, table_id, flow_data_variable_id, keys, value, mask=0xffffffff):
    command=bebaproto.OFPSC_EXP_SET_FLOW_DATA_VAR

    key_count=len(keys)

    if flow_data_variable_id<0 or flow_data_variable_id>bebaproto.MAX_FLOW_DATA_VAR_NUM-1:
        LOG.debug("OFPExpMsgSetFlowDataVariable: invalid flow_data_variable_id")

    if key_count > bebaproto.MAX_KEY_LEN:
        key_count = 0
        LOG.debug("OFPExpMsgSetFlowDataVariable: Number of keys given > MAX_KEY_LEN")

    data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command)
    data+=struct.pack(bebaproto.OFP_EXP_STATE_MOD_SET_FLOW_DATA_VAR_PACK_STR, table_id, flow_data_variable_id, key_count, value, mask)
    field_extract_format='!B'

    if key_count <= bebaproto.MAX_KEY_LEN:
        for f in range(key_count):
                data+=struct.pack(field_extract_format,keys[f])
    
    exp_type=bebaproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpMsgHeaderFieldExtract(datapath, table_id, extractor_id, field):
    command=bebaproto.OFPSC_EXP_SET_HEADER_FIELD_EXTRACTOR

    if extractor_id<0 or extractor_id>bebaproto.MAX_HEADER_FIELDS-1:
        LOG.debug("OFPExpMsgHeaderFieldExtract: invalid extractor_id")

    # TODO Davide: check if OXM_LENGTH(field)<=32 bit

    data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command)
    data+=struct.pack(bebaproto.OFP_EXP_STATE_MOD_SET_HEADER_EXTRACTOR_PACK_STR,table_id,extractor_id,field)

    exp_type=bebaproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)


def OFPExpMsgSetFlowState(datapath, state, keys, table_id, idle_timeout=0, idle_rollback=0, hard_timeout=0, hard_rollback=0, state_mask=0xffffffff):
    key_count=len(keys)

    if key_count > bebaproto.MAX_KEY_LEN:
        key_count = 0
        LOG.debug("OFPExpMsgSetFlowState: Number of keys given > MAX_KEY_LEN")

    command=bebaproto.OFPSC_EXP_SET_FLOW_STATE
    data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command)
    data+=struct.pack(bebaproto.OFP_EXP_STATE_MOD_SET_FLOW_STATE_PACK_STR, table_id, key_count, state, state_mask, hard_rollback, idle_rollback, hard_timeout*1000000, idle_timeout*1000000)
    field_extract_format='!B'

    if key_count <= bebaproto.MAX_KEY_LEN:
        for f in range(key_count):
                data+=struct.pack(field_extract_format,keys[f])
    
    exp_type=bebaproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpMsgDelFlowState(datapath, keys, table_id):
    key_count=len(keys)

    if key_count > bebaproto.MAX_KEY_LEN:
        key_count = 0
        LOG.debug("OFPExpMsgDelFlowState: Number of keys given > MAX_KEY_LEN")

    command=bebaproto.OFPSC_EXP_DEL_FLOW_STATE
    data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, command)
    data+=struct.pack(bebaproto.OFP_EXP_STATE_MOD_DEL_FLOW_STATE_PACK_STR,table_id,key_count)
    field_extract_format='!B'

    if key_count <= bebaproto.MAX_KEY_LEN:
        for f in range(key_count):
                data+=struct.pack(field_extract_format,keys[f])
    
    exp_type=bebaproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpSetGlobalState(datapath, global_state, global_state_mask=0xffffffff):
    data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, bebaproto.OFPSC_EXP_SET_GLOBAL_STATE)
    data+=struct.pack(bebaproto.OFP_EXP_STATE_MOD_SET_GLOBAL_STATE_PACK_STR,global_state,global_state_mask)
    
    exp_type=bebaproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpResetGlobalState(datapath):
    data=struct.pack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, bebaproto.OFPSC_EXP_RESET_GLOBAL_STATE)
    
    exp_type=bebaproto.OFPT_EXP_STATE_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpStateStatsMultipartRequest(datapath, table_id=ofproto.OFPTT_ALL, state=None, match=None):
    flags = 0 # Zero or ``OFPMPF_REQ_MORE``
    get_from_state = 1
    if state is None:
        get_from_state = 0
        state = 0
        
    if match is None:
        match = ofproto_parser.OFPMatch()

    data=bytearray()
    msg_pack_into(bebaproto.OFP_STATE_STATS_REQUEST_0_PACK_STR, data, 0, table_id, get_from_state, state)
    
    offset=bebaproto.OFP_STATE_STATS_REQUEST_0_SIZE
    match.serialize(data, offset)

    exp_type=bebaproto.OFPMP_EXP_STATE_STATS
    return ofproto_parser.OFPExperimenterStatsRequest(datapath=datapath, flags=flags, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpStateStatsMultipartRequestAndDelete(datapath, table_id=ofproto.OFPTT_ALL, state=None, match=None):
    flags = 0 # Zero or ``OFPMPF_REQ_MORE``
    get_from_state = 1
    if state is None:
        get_from_state = 0
        state = 0
        
    if match is None:
        match = ofproto_parser.OFPMatch()

    data=bytearray()
    msg_pack_into(bebaproto.OFP_STATE_STATS_REQUEST_0_PACK_STR, data, 0, table_id, get_from_state, state)
    
    offset=bebaproto.OFP_STATE_STATS_REQUEST_0_SIZE
    match.serialize(data, offset)

    exp_type=bebaproto.OFPMP_EXP_STATE_STATS_AND_DELETE
    return ofproto_parser.OFPExperimenterStatsRequest(datapath=datapath, flags=flags, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

""" 
State Sync: Controller asks for flows in a specific state
"""
def OFPExpGetFlowsInState(datapath, table_id=ofproto.OFPTT_ALL, state=None):
    return OFPExpStateStatsMultipartRequest(datapath=datapath, table_id=table_id, state=state, match=None)
""" 
State Sync: Controller asks for the state of a flow
"""
def OFPExpGetFlowState(datapath, table_id=ofproto.OFPTT_ALL, match=None):
    return OFPExpStateStatsMultipartRequest(datapath=datapath, table_id=table_id, state=None, match=match)
""" 
State Sync: This function returns the global state of a switch
"""
def OFPExpGlobalStateStatsMultipartRequest(datapath):
    flags = 0 # Zero or ``OFPMPF_REQ_MORE``    
    data=bytearray()
    exp_type=bebaproto.OFPMP_EXP_GLOBAL_STATE_STATS
    return ofproto_parser.OFPExperimenterStatsRequest(datapath=datapath, flags=flags, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPErrorExperimenterMsg_handler(ev):
    msg = ev.msg
    LOG.debug('')
    LOG.debug('OFPErrorExperimenterMsg received.')
    LOG.debug('version=%s, msg_type=%s, msg_len=%s, xid=%s',hex(msg.version),
        hex(msg.msg_type), hex(msg.msg_len), hex(msg.xid))
    LOG.debug(' `-- msg_type: %s',ofproto.ofp_msg_type_to_str(msg.msg_type))
    LOG.debug("OFPErrorExperimenterMsg(type=%s, exp_type=%s, experimenter_id='%s')",hex(msg.type),
        hex(msg.exp_type), hex(msg.experimenter))
    LOG.debug(' |-- type: %s',ofproto.ofp_error_type_to_str(msg.type))
    LOG.debug(' |-- exp_type: %s',bebaproto.ofp_error_code_to_str(msg.type,msg.exp_type))
    LOG.debug(' |-- experimenter_id: %s',hex(msg.experimenter))
    (version, msg_type, msg_len, xid) = struct.unpack_from(ofproto.OFP_HEADER_PACK_STR,
                              six.binary_type(msg.data))
    LOG.debug(
            ' `-- data: version=%s, msg_type=%s, msg_len=%s, xid=%s',
            hex(version), hex(msg_type), hex(msg_len), hex(xid))

def OFPExpMsgAddPktTmp(datapath, pkttmp_id, pkt_data):
    command=bebaproto.OFPSC_ADD_PKTTMP
    data=struct.pack(bebaproto.OFP_EXP_PKTTMP_MOD_PACK_STR, command)
    data+=struct.pack(bebaproto.OFP_EXP_PKTTMP_MOD_ADD_PKTTMP_PACK_STR, pkttmp_id)
    data+=pkt_data
    #print("Data:%s\n" % ''.join( [ "%02X " % ord( x ) for x in data ] ).strip())
    
    exp_type=bebaproto.OFPT_EXP_PKTTMP_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

def OFPExpMsgDelPktTmp(datapath, pkttmp_id):
    command=bebaproto.OFPSC_DEL_PKTTMP
    data=struct.pack(bebaproto.OFP_EXP_PKTTMP_MOD_PACK_STR, command)
    data+=struct.pack(bebaproto.OFP_EXP_PKTTMP_MOD_DEL_PKTTMP_PACK_STR, pkttmp_id)
    #LOG.error("OFPExpMsgSetFlowState: Number of keys given > MAX_KEY_LEN")
    
    exp_type=bebaproto.OFPT_EXP_PKTTMP_MOD
    return ofproto_parser.OFPExperimenter(datapath=datapath, experimenter=0xBEBABEBA, exp_type=exp_type, data=data)

class OFPInstructionInSwitchPktGen(ofproto_parser.OFPInstruction):
    """
    In Switch Packet Generation instruction

    This instruction triggers the generation of a packet.

    ================ ======================================================
    Attribute        Description
    ================ ======================================================
    type             OFPIT_EXPERIMENTER
    experimenter_id  BEBA_VENDOR_ID
    instr_type       OFPIT_IN_SWITCH_PKT_GEN
    actions          list of OpenFlow action class
    ================ ======================================================

    """
    def __init__(self, pkttmp_id, actions=None, len_=None):
        super(OFPInstructionInSwitchPktGen, self).__init__()
        self.type = ofproto.OFPIT_EXPERIMENTER
        self.experimenter_id = bebaproto.BEBA_EXPERIMENTER_ID
        self.instr_type = bebaproto.OFPIT_IN_SWITCH_PKT_GEN
        self.pkttmp_id = pkttmp_id
        for a in actions:
            assert isinstance(a, ofproto_parser.OFPAction)
        self.actions = actions

    @classmethod
    def parser(cls, buf, offset):
        (type_, len_, experimenter_id_, instr_type_) = struct.unpack_from(
            bebaproto.OFP_INSTRUCTION_INSWITCH_PKT_GEN_PACK_STR,
            buf, offset)

        offset += bebaproto.OFP_INSTRUCTION_INSWITCH_PKT_GEN_SIZE
        actions = []
        actions_len = len_ - bebaproto.OFP_INSTRUCTION_INSWITCH_PKT_GEN_SIZE
        while actions_len > 0:
            a = ofproto_parser.OFPAction.parser(buf, offset)
            actions.append(a)
            actions_len -= a.len
            offset += a.len

        inst = cls(type_, actions)
        inst.len = len_
        inst.experimenter_id = experimenter_id_
        inst.instr_type = instr_type_
        return inst

    def serialize(self, buf, offset):
        action_offset = offset + bebaproto.OFP_INSTRUCTION_INSWITCH_PKT_GEN_SIZE
        if self.actions:
            for a in self.actions:
                a.serialize(buf, action_offset)
                action_offset += a.len

        self.len = action_offset - offset
        pad_len = utils.round_up(self.len, 8) - self.len
        msg_pack_into("%dx" % pad_len, buf, action_offset)
        self.len += pad_len

        msg_pack_into(bebaproto.OFP_INSTRUCTION_INSWITCH_PKT_GEN_PACK_STR,
                      buf, offset, self.type, self.len, self.experimenter_id,
                      self.instr_type, self.pkttmp_id)

class OFPStateEntry(object):
    def __init__(self, key_count=None, key=None, state=None, flow_data_var=None):
        super(OFPStateEntry, self).__init__()
        
        self.key_count=key_count
        self.key = key
        self.state = state
        self.flow_data_var = flow_data_var
    
    @classmethod
    def parser(cls, buf, offset):
        entry = OFPStateEntry()

        key_count = struct.unpack_from('!I', buf, offset)
        entry.key_count = key_count[0]
        offset += 4
        entry.key=[]
        if entry.key_count <= bebaproto.MAX_KEY_LEN:
            for f in range(entry.key_count):
                key=struct.unpack_from('!B',buf,offset,)
                entry.key.append(key[0])
                offset +=1
        offset += (bebaproto.MAX_KEY_LEN - entry.key_count)

        state = struct.unpack_from('!I', buf, offset)
        entry.state=state[0]
        offset += 4

        entry.flow_data_var = []
        for f in range(bebaproto.MAX_FLOW_DATA_VAR_NUM):
            flow_data = struct.unpack_from('!I', buf, offset,)
            entry.flow_data_var.append(flow_data[0])
            offset += 4

        return entry

class OFPStateStats(StringifyMixin):
    def __init__(self, table_id=None, dur_sec=None, dur_nsec=None, field_count=None, fields=None, 
        entry=None,length=None, hard_rb=None, idle_rb=None, hard_to=None, idle_to=None):
        super(OFPStateStats, self).__init__()
        self.length = 0
        self.table_id = table_id
        self.dur_sec = dur_sec
        self.dur_nsec = dur_nsec
        self.field_count = field_count
        self.fields = fields
        self.entry = entry
        self.hard_to = hard_to
        self.hard_rb = hard_rb
        self.idle_to = idle_to
        self.hard_rb = hard_rb
        
    @classmethod
    def parser(cls, buf, offset=0):
        state_stats_list = []
        
        for i in range(len(buf)/bebaproto.OFP_STATE_STATS_SIZE):
            state_stats = cls()

            (state_stats.length, state_stats.table_id, state_stats.dur_sec,
                state_stats.dur_nsec, state_stats.field_count) = struct.unpack_from(
                bebaproto.OFP_STATE_STATS_0_PACK_STR, buf, offset)
            offset += bebaproto.OFP_STATE_STATS_0_SIZE

            state_stats.fields=[]
            field_extract_format='!I'
            if state_stats.field_count <= bebaproto.MAX_FIELD_COUNT:
                for f in range(state_stats.field_count):
                    field=struct.unpack_from(field_extract_format,buf,offset)
                    state_stats.fields.append(field[0])
                    offset +=4
            offset += ((bebaproto.MAX_FIELD_COUNT-state_stats.field_count)*4)
            state_stats.entry = OFPStateEntry.parser(buf, offset)
            offset += bebaproto.OFP_STATE_STATS_ENTRY_SIZE

            (state_stats.hard_rb, state_stats.idle_rb,state_stats.hard_to, state_stats.idle_to) = struct.unpack_from(
                bebaproto.OFP_STATE_STATS_1_PACK_STR, buf, offset)
            offset += bebaproto.OFP_STATE_STATS_1_SIZE
            state_stats_list.append(state_stats)

        return state_stats_list

class OFPGlobalStateStats(StringifyMixin):
    def __init__(self, global_state=None):
        super(OFPGlobalStateStats, self).__init__()
        self.global_state = global_state
        
    @classmethod
    def parser(cls, buf, offset):
        global_state_stats = cls()

        (global_state_stats.global_state, ) = struct.unpack_from('!4xI', buf, offset)

        return global_state_stats

def get_field_string(field,key,key_count,offset):
    if field==ofproto.OXM_OF_IN_PORT:
        if key_count!=0:
            length = 4
            value = struct.unpack('<I', array('B',key[offset:offset+length]))[0]
            return ("in_port=\"%d\""%(value),length)
        else:
            return ("in_port=*",0)
    elif field==ofproto.OXM_OF_IN_PHY_PORT:
        if key_count!=0:
            length = 4
            VLAN_VID_MASK = 0x0fff
            value = struct.unpack('<I', array('B',key[offset:offset+length]))[0] & VLAN_VID_MASK
            return ("in_phy_port=\"%d\""%(value),length)
        else:
            return ("in_phy_port=*",0)
    elif field==ofproto.OXM_OF_VLAN_VID:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("vlan_vid=\"%d\""%(value),length)
        else:
            return ("vlan_vid=*",0)
    elif field==ofproto.OXM_OF_VLAN_PCP:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0] & 0x7
            return ("vlan_pcp=\"%d\""%(value),length)
        else:
            return ("vlan_pcp=*",0)
    elif field==ofproto.OXM_OF_ETH_TYPE:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("eth_type=\"%d\""%(value),length)
        else:
            return ("eth_type=*",0)
    elif field==ofproto.OXM_OF_TCP_SRC:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("tcp_src=\"%d\""%(value),length)
        else:
            return ("tcp_src=*",0)
    elif field==ofproto.OXM_OF_TCP_DST:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("tcp_dst=\"%d\""%(value),length)
        else:
            return ("tcp_dst=*",0)
    elif field==ofproto.OXM_OF_TCP_FLAGS:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("tcp_flags=\"%d\""%(value),length)
        else:
            return ("tcp_flags=*",0)
    elif field==ofproto.OXM_OF_UDP_SRC:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("udp_src=\"%d\""%(value),length)
        else:
            return ("udp_src=*",0)
    elif field==ofproto.OXM_OF_UDP_DST:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("udp_dst=\"%d\""%(value),length)
        else:
            return ("udp_dst=*",0)
    elif field==ofproto.OXM_OF_SCTP_SRC:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("sctp_src=\"%d\""%(value),length)
        else:
            return ("sctp_src=*",0)
    elif field==ofproto.OXM_OF_SCTP_DST:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("sctp_dst=\"%d\""%(value),length)
        else:
            return ("sctp_dst=*",0)
    elif field==ofproto.OXM_OF_ETH_SRC:
        if key_count!=0:
            length = 6
            return ("eth_src=\"%02x:%02x:%02x:%02x:%02x:%02x\""%(key[offset],key[offset+1],key[offset+2],key[offset+3],key[offset+4],key[offset+5]),length)
        else:
            return ("eth_src=*",0)
    elif field==ofproto.OXM_OF_ETH_DST:
        if key_count!=0:
            length = 6
            return ("eth_dst=\"%02x:%02x:%02x:%02x:%02x:%02x\""%(key[offset],key[offset+1],key[offset+2],key[offset+3],key[offset+4],key[offset+5]),length)
        else:
            return ("eth_dst=*",0)
    elif field==ofproto.OXM_OF_IPV4_SRC:
        if key_count!=0:
            length = 4
            return ("ipv4_src=\"%d.%d.%d.%d\""%(key[offset],key[offset+1],key[offset+2],key[offset+3]),length)
        else:
            return ("ipv4_src=*",0)
    elif field==ofproto.OXM_OF_IPV4_DST:
        if key_count!=0:
            length = 4
            return ("ipv4_dst=\"%d.%d.%d.%d\""%(key[offset],key[offset+1],key[offset+2],key[offset+3]),length)
        else:
            return ("ipv4_dst=*",0)
    elif field==ofproto.OXM_OF_IP_PROTO:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0]
            return ("ip_proto=\"%d\""%(value),length)
        else:
            return ("ip_proto=*",0)
    elif field==ofproto.OXM_OF_IP_DSCP:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0] & 0x3f
            return ("ip_dscp=\"%d\""%(value),length)
        else:
            return ("ip_dscp=*",0)
    elif field==ofproto.OXM_OF_IP_ECN:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0] & 0x3
            return ("ip_ecn=\"%d\""%(value),length)
        else:
            return ("ip_ecn=*",0)
    elif field==ofproto.OXM_OF_ICMPV4_TYPE:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0]
            return ("icmpv4_type=\"%d\""%(value),length)
        else:
            return ("icmpv4_type=*",0)
    elif field==ofproto.OXM_OF_ICMPV4_CODE:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0]
            return ("icmpv4_code=\"%d\""%(value),length)
        else:
            return ("icmpv4_code=*",0)
    elif field==ofproto.OXM_OF_ARP_SHA:
        if key_count!=0:
            length = 6
            return ("arp_sha=\"%02x:%02x:%02x:%02x:%02x:%02x\""%(key[offset],key[offset+1],key[offset+2],key[offset+3],key[offset+4],key[offset+5]),length)
        else:
            return ("arp_sha=*",0)
    elif field==ofproto.OXM_OF_ARP_THA:
        if key_count!=0:
            length = 6
            return ("arp_tha=\"%02x:%02x:%02x:%02x:%02x:%02x\""%(key[offset],key[offset+1],key[offset+2],key[offset+3],key[offset+4],key[offset+5]),length)
        else:
            return ("arp_tha=*",0)
    elif field==ofproto.OXM_OF_ARP_SPA:
        if key_count!=0:
            length = 4
            return ("arp_spa=\"%d.%d.%d.%d\""%(key[offset],key[offset+1],key[offset+2],key[offset+3]),length)
        else:
            return ("arp_spa=*",0)
    elif field==ofproto.OXM_OF_ARP_TPA:
        if key_count!=0:
            length = 4
            return ("arp_tpa=\"%d.%d.%d.%d\""%(key[offset],key[offset+1],key[offset+2],key[offset+3]),length)
        else:
            return ("arp_tpa=*",0)
    elif field==ofproto.OXM_OF_ARP_OP:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("arp_op=\"%d\""%(value),length)
        else:
            return ("arp_op=*",0)
    elif field==ofproto.OXM_OF_IPV6_SRC:
        if key_count!=0:
            length = 16
            value = []
            for q in range(8): 
                value[q]=format(struct.unpack('<H', array('B',key[offset:offset+2]))[0],'x')
                offset += 2
            return ("nw_src_ipv6=\"%s:%s:%s:%s:%s:%s:%s:%s\""%(value[0],value[1],value[2],value[3],value[4],value[5],value[6],value[7]),length)
        else:
            return ("nw_src_ipv6=*",0)
    elif field==ofproto.OXM_OF_IPV6_DST:
        if key_count!=0:
            length = 16
            value = []
            for q in range(8): 
                value.append(format(struct.unpack('<H', array('B',key[offset:offset+2]))[0],'x'))
                offset += 2
            return ("nw_dst_ipv6=\"%s:%s:%s:%s:%s:%s:%s:%s\""%(value[0],value[1],value[2],value[3],value[4],value[5],value[6],value[7]),length)
        else:
            return ("nw_dst_ipv6=*",0)
    elif field==ofproto.OXM_OF_IPV6_ND_TARGET:
        if key_count!=0:
            length = 16
            value = []
            for q in range(8): 
                value[q]=format(struct.unpack('<H', array('B',key[offset:offset+2]))[0],'x')
                offset += 2
            return ("ipv6_nd_target=\"%s:%s:%s:%s:%s:%s:%s:%s\""%(value[0],value[1],value[2],value[3],value[4],value[5],value[6],value[7]),length)
        else:
            return ("ipv6_nd_target=*",0)
    elif field==ofproto.OXM_OF_IPV6_ND_SLL:
        if key_count!=0:
            length = 6
            return ("ipv6_nd_sll=\"%02x:%02x:%02x:%02x:%02x:%02x\""%(key[offset],key[offset+1],key[offset+2],key[offset+3],key[offset+4],key[offset+5]),length)
        else:
            return ("ipv6_nd_sll=*",0)
    elif field==ofproto.OXM_OF_IPV6_ND_TLL:
        if key_count!=0:
            length = 6
            return ("ipv6_nd_tll=\"%02x:%02x:%02x:%02x:%02x:%02x\""%(key[offset],key[offset+1],key[offset+2],key[offset+3],key[offset+4],key[offset+5]),length)
        else:
            return ("ipv6_nd_tll=*",0)
    elif field==ofproto.OXM_OF_IPV6_FLABEL:
        if key_count!=0:
            length = 4
            value = struct.unpack('<I', array('B',key[offset:offset+length]))[0] & 0x000fffff
            return ("ipv6_flow_label=\"%d\""%(value),length)    
        else:
            return ("ipv6_flow_label=*",0)
    elif field==ofproto.OXM_OF_ICMPV6_TYPE:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0]
            return ("icmpv6_type=\"%d\""%(value),length)
        else:
            return ("icmpv6_type=*",0)
    elif field==ofproto.OXM_OF_ICMPV6_CODE:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0]
            return ("icmpv6_code=\"%d\""%(value),length)
        else:
            return ("icmpv6_code=*",0)
    elif field==ofproto.OXM_OF_MPLS_LABEL:
        if key_count!=0:
            length = 4
            value = struct.unpack('<I', array('B',key[offset:offset+length]))[0] & 0x000fffff
            return ("mpls_label=\"%d\""%(value),length)  
        else:
            return ("mpls_label=*",0)
    elif field==ofproto.OXM_OF_MPLS_TC:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0] & 0x3
            return ("mpls_tc=\"%d\""%(value),length)
        else:
            return ("mpls_tc=*",0)
    elif field==ofproto.OXM_OF_MPLS_BOS:
        if key_count!=0:
            length = 1
            value = struct.unpack('<B', array('B',key[offset:offset+length]))[0] & 0x1
            return ("mpls_bos=\"%d\""%(value),length)
        else:
            return ("mpls_bos=*",0)
    elif field==ofproto.OXM_OF_PBB_ISID:
        if key_count!=0:
            length = 4
            value = struct.unpack('<I', array('B',key[offset:offset+length]))[0]
            return ("pbb_isid=\"%d\""%(value),length)  
        else:
            return ("pbb_isid=*",0)
    elif field==ofproto.OXM_OF_TUNNEL_ID:
        if key_count!=0:
            length = 8
            value = struct.unpack('<Q', array('B',key[offset:offset+length]))[0]
            return ("tunnel_id=\"%d\""%(value),length)
        else:
            return ("tunnel_id=*",0)
    elif field==ofproto.OXM_OF_IPV6_EXTHDR:
        if key_count!=0:
            length = 2
            value = struct.unpack('<H', array('B',key[offset:offset+length]))[0]
            return ("ext_hdr=\"%d\""%(value),length)
        else:
            return ("ext_hdr=*",0)

def state_entry_key_to_str(state_stats):
    offset = 0
    s = ''
    for field in state_stats.fields[:state_stats.field_count]:
        (string,field_len) = get_field_string(field,state_stats.entry.key,state_stats.entry.key_count,offset)
        s += string
        offset += field_len
        if field != state_stats.fields[state_stats.field_count-1]:
            s += ","
    return s


'''
Global states are 32, numbered from 0 to 31 from right to left

masked_global_state_from_str("0*1100")       -> **************************0*1100 -> (12,47)
masked_global_state_from_str("0*1100",12)    -> ***************0*1100*********** -> (49152, 192512)

'''
def masked_global_state_from_str(string,offset=0):
    import re
    str_len=len(string)
    if re.search('r[^01*]', string) or str_len>32 or str_len<1:
        print("ERROR: global_state string can only contain 0,1 and * and must have at least 1 bit and at most 32 bits!")
        return (0,0)
    if offset>31 or offset<0:
        print("ERROR: offset must be in range 0-31!")
        return (0,0)
    if str_len+offset>32:
        print("ERROR: offset is too big")
        return (0,0)

    mask=['0']*32
    value=['0']*32

    for i in range(offset,str_len+offset):
        if not string[str_len-1+offset-i]=="*":
            mask[31-i]="1"
            value[31-i]=string[str_len-1+offset-i]
    mask=''.join(mask)
    value=''.join(value)
    return (int(value,2),int(mask,2))
'''
state field is 32bit long
Thanks to the mask we can divide the field in multiple substate matchable with masks.

substate(state,section,sec_count)
state = state to match
section = number of the selected subsection (starts from 1 from the right)
sec_count = number of how many subsection the state field has been divided

substate(5,2,4)   -> |********|********|00000101|********|-> (1280,16711680)

'''
def substate(state,section,sec_count):
    
    if not isinstance(state, int) or not isinstance(section, int) or not isinstance(sec_count, int):
        print("ERROR: parameters must be integers!")
        return(0,0)
    if state < 0 or section < 0 or sec_count < 0:
        print("ERROR: parameters must be positive!")
        return(0,0)
    if 32%sec_count != 0:
        print("ERROR: the number of sections must be a divisor of 32")
        return(0,0)
    section_len = 32/sec_count
    if state >= pow(2,section_len):
        print("ERROR: state exceed the section's length")
        return(0,0)
    if section not in range (1,sec_count+1):
        print("ERROR: section not exist. It must be between 1 and sec_count")
        return(0,0)

    sec_count = sec_count -1
    count = 1
    starting_point = section*section_len
    
    mask=['0']*32
    value=['0']*32
    bin_state=['0']*section_len
    
    state = bin(state)
    state = ''.join(state[2:])
    
    for i in range(0,len(state)):
        bin_state [section_len-1-i]= state[len(state)-1-i]
    
    for i in range(starting_point,starting_point+section_len):
        value[31-i]=bin_state[section_len - count]
        count = count + 1 
        mask[31-i]="1"
    
    mask=''.join(mask)
    value=''.join(value)
    return (int(value,2),int(mask,2))

###############################################################################################################################
'''
[Beba to Open vSwitch wrapper]

An Beba application can be run by an Open vSwitch softswitch without Beba support by adding
'@Beba2OVSWrapper' just before def switch_features_handler(self, ev), after '@set_ev_cls()'

$ sudo mn --topo single,4 --mac --switch ovsk --controller remote    --->    starts Open vSwitch (OpenFlow only)
$ sudo mn --topo single,4 --mac --switch user --controller remote    --->    starts ofsoftswitch13 (OpenFlow + Beba)
$ ryu-manager [app_name]


How stuff works:
we need to intercept any message containing Beba code (Beba messages, FlowMod matching on 'state', FlowMod containing
SetState action, ...). The best way is intercepting any call to send_msg() in order to filter/modify/drop the outgoing message.
We don't want to touch Ryu code and we'd like minimal modifications to Beba applications code.
send_msg() is a method from Datapath class, so we need to extend it to override send_msg().
The Datapath object 'datapath' should be casted to a OVSDatapath object and the best moment is when the controller
communicates with the switch for the first time (so in switch_features_handler()).
We want to cast the object just before the execution of the user-defined handler, so we can use a decorator to execute some 
additional code before the user-defined function. A decorator is a function that takes a function object as an argument, and
returns a function object as a return value.
'''

from ryu.controller.controller import Datapath
from sets import Set

'''
OVSDatapath class inherits Datapath class to override send_msg() method in order to intercept and adapt Beba messages.
Finally the original send_msg() is called, when appropriate (e.g. messages OFPExpMsgConfigureStatefulTable and OFPExpMsgKeyExtract
just update OVSDatapath internal state withtout being sent to the switch)
'''
class OVSDatapath(Datapath):
    def send_msg(self, msg):
        '''
        In Beba a stateful stage has a state table and a flow table with the same table_id.
        In Open vSwitch a stateful stage has two separated flow tables with adjacent table_ids
        '''
        def get_state_table_id(table_id):
            return 2*table_id
        def get_flow_table_id(table_id):
            return 2*table_id+1

        if isinstance(msg,ofproto_parser.OFPExperimenter) and msg.experimenter==0xBEBABEBA and msg.exp_type==bebaproto.OFPT_EXP_STATE_MOD:
            # We are forced to unpack because OFPExpMsgConfigureStatefulTable is not a class with attributes; for simplicity it's a
            # method returning an instance of OFPExperimenter with the packed payload (refactoring!?!)
            command_offset = struct.calcsize(bebaproto.OFP_EXP_STATE_MOD_PACK_STR)
            (command,) = struct.unpack(bebaproto.OFP_EXP_STATE_MOD_PACK_STR, msg.data[:command_offset])
            if command == bebaproto.OFPSC_EXP_STATEFUL_TABLE_CONFIG:
                (table_id,stateful) = struct.unpack(bebaproto.OFP_EXP_STATE_MOD_STATEFUL_TABLE_CONFIG_PACK_STR, msg.data[command_offset:command_offset+struct.calcsize(bebaproto.OFP_EXP_STATE_MOD_STATEFUL_TABLE_CONFIG_PACK_STR)])

                # "control flow" table miss in State Table
                # OVS have all port numbers into the 16-bit range (like in OF1.0), while later OF version use 32-bit port numbers.
                # NXActionResubmitTable needs 16-bit port numbers, so we cannot put ofproto.OFPP_IN_PORT: we put 0xfff8 (OFPP_IN_PORT=0xfff8 in OF1.0)
                # https://github.com/openvswitch/ovs/blob/master/OPENFLOW-1.1%2B.md
                match = ofproto_parser.OFPMatch(reg1=0)
                actions = [ofproto_parser.OFPActionSetField(reg1=1),
                    ofproto_parser.NXActionResubmitTable(0xfff8,get_state_table_id(table_id)),
                    ofproto_parser.NXActionResubmitTable(0xfff8,get_flow_table_id(table_id))]
                inst = [ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = ofproto_parser.OFPFlowMod(datapath=self, table_id=get_state_table_id(table_id), priority=10, match=match, instructions=inst)
                super(OVSDatapath, self).send_msg(mod)

                # "return DEFAULT state" in State Table
                match = ofproto_parser.OFPMatch(reg1=1)
                actions = [ofproto_parser.OFPActionSetField(reg0=0)]
                inst = [ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = ofproto_parser.OFPFlowMod(datapath=self, table_id=get_state_table_id(table_id), priority=10, match=match, instructions=inst)
                super(OVSDatapath, self).send_msg(mod)

                # keep track of stateful stages (useful when handling GotoTable instructions)
                self.stateful_stages_in_use.add(table_id)

                # OFPExpMsgConfigureStatefulTable msg is dropped
                return
            elif command == bebaproto.OFPSC_EXP_SET_L_EXTRACTOR or command == bebaproto.OFPSC_EXP_SET_U_EXTRACTOR:
                (table_id,field_count) = struct.unpack(bebaproto.OFP_EXP_STATE_MOD_EXTRACTOR_PACK_STR,msg.data[command_offset:command_offset+struct.calcsize(bebaproto.OFP_EXP_STATE_MOD_EXTRACTOR_PACK_STR)])
                if field_count>0:
                    fields_offset = command_offset+struct.calcsize(bebaproto.OFP_EXP_STATE_MOD_EXTRACTOR_PACK_STR)
                    field_size = struct.calcsize('!I')
                    if command == bebaproto.OFPSC_EXP_SET_L_EXTRACTOR:
                        self.lookup_scope[table_id] = []
                        for f in range(field_count):
                            current_field_offset = fields_offset+field_size*f
                            self.lookup_scope[table_id].append( struct.unpack('!I',msg.data[current_field_offset : current_field_offset+field_size])[0] )
                    elif command == bebaproto.OFPSC_EXP_SET_U_EXTRACTOR:
                        self.update_scope[table_id] = []
                        for f in range(field_count):
                            current_field_offset = fields_offset+field_size*f
                            self.update_scope[table_id].append( struct.unpack('!I',msg.data[current_field_offset : current_field_offset+field_size])[0] )
                else:
                    LOG.debug("ERROR: no fields in lookup/update scope!")
                # OFPExpMsgKeyExtract msg is dropped
                return
            elif command == bebaproto.OFPSC_EXP_SET_FLOW_STATE:
                # We should send a FlowMod MODIFY by converting 'keys' into FlowMod's match fields and 'state' into OFPActionSetField(reg0=state) '''
                '''
                TODO: timeouts handling. Up to now timeouts are ignored (see comments below in OFPAT_EXP_SET_STATE)

                TODO: 'state_mask' handling
                Until now 'state_mask' is ignored because in OF1.3 SetField actions does not allow mask (only OF1.5 allows it with EXT-314)
                In fact ovs-ofctl translates a set_field into a reg_load when we force OF version to 1.3.
                sudo ovs-ofctl add-flow s1 -O OpenFlow13 "table=0 action=set_field:1/5->reg0"   -->     actions=load:0x1->NXM_NX_REG0[0],load:0->NXM_NX_REG0[2]
                sudo ovs-ofctl add-flow s1 -O OpenFlow13 "table=0 action=set_field:1->reg0"     -->     actions=set_field:0x1->reg0
                Seacrh for "set_field:value[/mask]->dst" in http://openvswitch.org/support/dist-docs/ovs-ofctl.8.txt
                Ryu API for OF1.3 does not include anymore NXActionRegLoad. If state_mask is 0xFFFFFFFF we can use set_field, otherwise
                we need another strategy. Maybe porting NXActionRegLoad from OF1.0?
                '''
                (table_id, key_count, state, state_mask, hard_rollback, idle_rollback, hard_timeout, idle_timeout) = struct.unpack(bebaproto.OFP_EXP_STATE_MOD_SET_FLOW_STATE_PACK_STR, msg.data[command_offset:command_offset+struct.calcsize(bebaproto.OFP_EXP_STATE_MOD_SET_FLOW_STATE_PACK_STR)])
                if key_count>0:
                    lookup_fields = {}
                    key_starting_offset = command_offset+struct.calcsize(bebaproto.OFP_EXP_STATE_MOD_SET_FLOW_STATE_PACK_STR)
                    key_offset = 0
                    # Parse the remaning payload to get the matching values of all lookup fields
                    for f in self.lookup_scope[table_id]:
                        field_bytes_num = ofproto_parser.OFPMatchField._FIELDS_HEADERS[f](f,0,0).oxm_len()
                        # if f is ofproto.OXM_OF_ETH_SRC then field_name would be 'eth_dst'
                        field_name = ofproto_parser._NXFlowSpec._parse_subfield( bytearray(struct.pack('!IH',f,0)) )[0]
                        key = list(struct.unpack('!'+'B'*field_bytes_num, msg.data[key_starting_offset+key_offset:key_starting_offset+key_offset+field_bytes_num]))
                        # We'd like something like lookup_fields['eth_dst']='00:00:00:0a:0a:0a'
                        lookup_fields[field_name] = self.bytes_to_match_value(f,key)
                        key_offset += field_bytes_num
                    self.add_prereq_match_to_dict(self.lookup_scope[table_id],lookup_fields)
                    match = ofproto_parser.OFPMatch(reg1=1,**lookup_fields)
                    actions = [ofproto_parser.OFPActionSetField(reg1=0),ofproto_parser.OFPActionSetField(reg0=state)]
                    inst = [ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = ofproto_parser.OFPFlowMod(datapath=self, cookie=0, cookie_mask=0,table_id=get_state_table_id(table_id),
                        command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, priority=100, buffer_id=ofproto.OFP_NO_BUFFER,
                        out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=match, instructions=inst)
                    super(OVSDatapath, self).send_msg(mod)
                else:
                    LOG.debug("ERROR: empty key in STATE_MOD message!")
                return
            elif command == bebaproto.OFPSC_EXP_DEL_FLOW_STATE:
                # We should send a FlowMod DELETE by converting 'keys' into FlowMod's match fields
                (table_id, key_count) = struct.unpack(bebaproto.OFP_EXP_STATE_MOD_DEL_FLOW_STATE_PACK_STR, msg.data[command_offset:command_offset+struct.calcsize(bebaproto.OFP_EXP_STATE_MOD_DEL_FLOW_STATE_PACK_STR)])
                if key_count>0:
                    lookup_fields = {}
                    key_starting_offset = command_offset+struct.calcsize(bebaproto.OFP_EXP_STATE_MOD_DEL_FLOW_STATE_PACK_STR)
                    key_offset = 0
                    # Parse the remaning payload to get the matching values of all lookup fields
                    for f in self.lookup_scope[table_id]:
                        field_bytes_num = ofproto_parser.OFPMatchField._FIELDS_HEADERS[f](f,0,0).oxm_len()
                        # if f is ofproto.OXM_OF_ETH_SRC then field_name would be 'eth_dst'
                        field_name = ofproto_parser._NXFlowSpec._parse_subfield( bytearray(struct.pack('!IH',f,0)) )[0]
                        key = list(struct.unpack('!'+'B'*field_bytes_num, msg.data[key_starting_offset+key_offset:key_starting_offset+key_offset+field_bytes_num]))
                        # We'd like something like lookup_fields['eth_dst']='00:00:00:0a:0a:0a'
                        lookup_fields[field_name] = self.bytes_to_match_value(f,key)
                        key_offset += field_bytes_num
                    self.add_prereq_match_to_dict(self.lookup_scope[table_id],lookup_fields)
                    match = ofproto_parser.OFPMatch(reg1=1,**lookup_fields)
                    mod = ofproto_parser.OFPFlowMod(datapath=self, cookie=0, cookie_mask=0,table_id=get_state_table_id(table_id),
                        command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0, priority=100, buffer_id=ofproto.OFP_NO_BUFFER,
                        out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=match)
                    super(OVSDatapath, self).send_msg(mod)
                else:
                    LOG.debug("ERROR: empty key in STATE_MOD message!")
                return
            elif command == bebaproto.OFPSC_EXP_SET_GLOBAL_STATE:
                ''' TODO: global states could be implemented by prepending a stage with just one table miss entry that sets reg8=global state value.
                We should send a FlowMod ADD. NB get_state_table_id() and get_flow_table_id() return value should be sincreased by 1 '''
                return
            elif command == bebaproto.OFPSC_EXP_RESET_GLOBAL_STATE:
                ''' TODO: We could send a FlowMod MOD that sets reg8=0 (or that just do GotoTable(1) ) in the table miss entry'''
                return
        elif isinstance(msg,ofproto_parser.OFPExperimenterStatsRequest) and msg.experimenter==0xBEBABEBA:
            if msg.exp_type==bebaproto.OFPMP_EXP_STATE_STATS:
                ''' TODO: In Open vSwitch the state table is a simple flow table => we could send a OFPMultipartRequest, maybe '''
            elif msg.exp_type==bebaproto.OFPMP_EXP_GLOBAL_STATE_STATS:
                ''' TODO: in Open vSwitch, global states are a flow entry in the first table => we could send a OFPMultipartRequest, maybe '''
            elif msg.exp_type==bebaproto.OFPMP_EXP_STATE_STATS_AND_DELETE:
                ''' TODO '''
            return
        elif isinstance(msg,ofproto_parser.OFPFlowMod):
            # [step 1 ] check for the presence of any Beba action in OFPInstructionActions
            for instr in msg.instructions:
                if isinstance(instr, ofproto_parser.OFPInstructionActions) and instr.type in [ofproto.OFPIT_WRITE_ACTIONS , ofproto.OFPIT_APPLY_ACTIONS]:
                    filtered_action_set = []
                    for act in instr.actions:
                        if isinstance(act, ofproto_parser.OFPActionExperimenterUnknown) and act.experimenter == 0xBEBABEBA:
                            (act_type,) = struct.unpack('!I', act.data[:struct.calcsize('!I')])
                            if act_type == bebaproto.OFPAT_EXP_SET_STATE:
                                (act_type, state, state_mask, table_id, hard_rollback, idle_rollback, hard_timeout, idle_timeout) = struct.unpack(bebaproto.OFP_EXP_ACTION_SET_STATE_PACK_STR, act.data[:struct.calcsize(bebaproto.OFP_EXP_ACTION_SET_STATE_PACK_STR)])
                                ''' TODO: timeouts handling. Up to now timeouts are ignored because OF flow entry's timeouts can be set only when a flow entry is added! (e.g. created for the first time) '''
                                ''' TODO: multiple rollback states
                                Rollback state!=0 could be supported with 2 learn actions, one with high priority (say 200) with the user-defined timeout and load:state->reg0,
                                the other with the classic priority 100, no timeouts and load:rollback->reg0. But how can we manage a state transitions with 2 (I/H) possible rollbacks? '''
                                specs = [ofproto_parser.NXFlowSpecMatch(dst=('reg1', 0),n_bits=32,src=1),
                                        ofproto_parser.NXFlowSpecLoad(dst=('reg1',0),n_bits=32,src=0)] 
                                specs.extend(self.generate_NXFlowSpecMatch_and_prereq(table_id))
                                specs.extend(self.generate_NXFlowSpecLoad(state,state_mask))
                                learn_action = ofproto_parser.NXActionLearn(table_id=get_state_table_id(table_id),priority=100,
                                    specs=specs)
                                filtered_action_set.append(learn_action)
                            elif act_type == bebaproto.OFPAT_EXP_SET_GLOBAL_STATE:
                                ''' TODO we could add an action learn() that install a flow entry in table 0 which sets reg8=global state value, with mask '''
                        else:
                            # non-Beba actions are left unchanged
                            filtered_action_set.append(act)
                    instr.actions = filtered_action_set
                elif isinstance(instr, ofproto_parser.OFPInstructionGotoTable):
                    # We cannot a priori know if stage 'table_id' will be stateful or not (maybe the OFPExpMsgConfigureStatefulTable has not already been sent
                    # or maybe it will not be sent at all). Instead of going to get_state_table_id(instr.table_id) OR get_flow_table_id(instr.table_id),
                    # a possible approach is going in any case to get_state_table_id(instr.table_id) and adding, if not already there, the table miss entry
                    # that sends packets to get_flow_table_id(instr.table_id).
                    if instr.table_id not in self.stateful_stages_in_use:
                        # "control flow" table miss in State Table (it's the same we'd install when we intercept an OFPExpMsgConfigureStatefulTable msg)
                        match = ofproto_parser.OFPMatch(reg1=0)
                        actions = [ofproto_parser.OFPActionSetField(reg1=1),
                            ofproto_parser.NXActionResubmitTable(0xfff8,get_state_table_id(instr.table_id)),
                            ofproto_parser.NXActionResubmitTable(0xfff8,get_flow_table_id(instr.table_id))]
                        inst = [ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                        mod = ofproto_parser.OFPFlowMod(datapath=self, table_id=get_state_table_id(instr.table_id), priority=10, match=match, instructions=inst)
                        super(OVSDatapath, self).send_msg(mod)

                        self.stateful_stages_in_use.add(instr.table_id)
                    instr.table_id = get_state_table_id(instr.table_id)

            # [step 2 ] check for he presence of any Beba match
            new_match_fields = []
            for (match_field_name,match_field_value) in msg.match._fields2:
                if match_field_name=='state':
                    new_match_fields.append(('reg0',match_field_value))
                elif match_field_name=='global_state':
                    continue # we should put new_match_fields.append(('reg8',match_field_value))
                else:
                    new_match_fields.append( (match_field_name,match_field_value) )
            msg.match._fields2 = new_match_fields

            msg.table_id = get_flow_table_id(msg.table_id)

        elif isinstance(msg,ofproto_parser.OFPGroupMod):
            for buck in msg.buckets:
                if isinstance(buck, ofproto_parser.OFPBucket):
                    filtered_action_set = []
                    for act in buck.actions:
                        if isinstance(act, ofproto_parser.OFPActionExperimenterUnknown) and act.experimenter == 0xBEBABEBA:
                            (act_type,) = struct.unpack('!I', act.data[:struct.calcsize('!I')])
                            if act_type == bebaproto.OFPAT_EXP_SET_STATE:
                                (act_type, state, state_mask, table_id, hard_rollback, idle_rollback, hard_timeout, idle_timeout) = struct.unpack(bebaproto.OFP_EXP_ACTION_SET_STATE_PACK_STR, act.data[:struct.calcsize(bebaproto.OFP_EXP_ACTION_SET_STATE_PACK_STR)])
                                ''' TODO: Timeouts are ignored because flow entry's timeouts can be changed only when the flow entry is added! (e.g. created for the first time)
                                For the same reason we cannot have rollback state different from zero! At most flow entry's timeouts can cause the entry to be deleted,
                                because it's not possible to change the load action with rollback state when a timeout expires! '''
                                specs = [ofproto_parser.NXFlowSpecMatch(dst=('reg1', 0),n_bits=32,src=1),
                                        ofproto_parser.NXFlowSpecLoad(dst=('reg1',0),n_bits=32,src=0)] 
                                specs.extend(self.generate_NXFlowSpecMatch_and_prereq(table_id))
                                specs.extend(self.generate_NXFlowSpecLoad(state,state_mask))
                                learn_action = ofproto_parser.NXActionLearn(table_id=get_state_table_id(table_id),priority=100,
                                    specs=specs)
                                filtered_action_set.append(learn_action)
                            elif act_type == bebaproto.OFPAT_EXP_SET_GLOBAL_STATE:
                                ''' TODO we could add an action learn() that install a flow entry in table 0 which sets reg8=global state value, with mask '''
                        else:
                            # non-Beba actions are left unchanged
                            filtered_action_set.append(act)
                    buck.actions = filtered_action_set

        return super(OVSDatapath, self).send_msg(msg)

    # It builds a set of NXFlowSpecMatch(dst=(LOOKUP_SCOPE_FIELD_OXM_NAME, 0),n_bits=OXM_FIELD_BITS_LENGTH,src=UPDATE_SCOPE_FIELD_OXM_NAME)
    # for each field of the lookup/update-scope. It adds to the set also an eventual match for being compliant to match prerequisites.
    def generate_NXFlowSpecMatch_and_prereq(self,table_id):
        # We save the result in the object (attribute self.flowSpecMatchDict) to avoid generate NXFlowSpecMatch multiple times for the same table!
        if table_id in self.flowSpecMatchDict and self.flowSpecMatchDict[table_id]!=Set([]):
            return self.flowSpecMatchDict[table_id]

        self.flowSpecMatchDict[table_id] = Set([]) # we use a Set instead of a list to avoid duplicates in case of 2 fields with the same pre-req

        # We create an hashable NXFlowSpecMatch to be able to use NXFlowSpecMatch in a Set
        class NXHashableFlowSpecMatch(ofproto_parser.NXFlowSpecMatch):
            def __hash__(self):
                return hash(str(self))
        
            def __eq__(self,other):
                return hash(str(self))==hash(str(other))

        # OVS wrapper transforms a state table lookup into a flow table lookup, hence we need to observe match prerequisites:
        # for example, if lookup-scope contains OXM_OF_IPV4_SRC, we need a learn containing a NXFlowSpecMatch matching eth_type=0x800.
        def add_prereq_match(flowSpecMatchDict,oxm_name,value):
            oxm_field = struct.unpack('!I',ofproto_parser._NXFlowSpec._serialize_subfield((oxm_name,0))[0:4])[0]
            n_bits = ofproto_parser.OFPMatchField._FIELDS_HEADERS[oxm_field](oxm_field,0,0).oxm_len()*8
            flowSpecMatchDict.add(NXHashableFlowSpecMatch(dst=(oxm_name,0),n_bits=n_bits,src=value))

        # This is the table 11 OF1.3 spec pag. 44
        ''' TODO: how can we handle pre-requisite such as OXM_OF_IP_DSCP with ETH TYPE=0x0800 or ETH TYPE=0x86dd ?? '''
        options = {
            ofproto.OXM_OF_IPV4_SRC: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'eth_type',0x800),
            ofproto.OXM_OF_IPV4_DST: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'eth_type',0x800),
            ofproto.OXM_OF_TCP_SRC: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'ip_proto',6),
            ofproto.OXM_OF_TCP_DST: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'ip_proto',6),
            ofproto.OXM_OF_UDP_SRC: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'ip_proto',17),
            ofproto.OXM_OF_UDP_DST: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'ip_proto',17),
            ofproto.OXM_OF_SCTP_SRC: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'ip_proto',132),
            ofproto.OXM_OF_SCTP_DST: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'ip_proto',132),
            ofproto.OXM_OF_ICMPV4_TYPE: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'ip_proto',1),
            ofproto.OXM_OF_ICMPV4_CODE: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'ip_proto',1),
            ofproto.OXM_OF_ARP_OP: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'eth_type',0x0806),
            ofproto.OXM_OF_ARP_SPA: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'eth_type',0x0806),
            ofproto.OXM_OF_ARP_TPA: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'eth_type',0x0806),
            ofproto.OXM_OF_ARP_SHA: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'eth_type',0x0806),
            ofproto.OXM_OF_ARP_THA: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'eth_type',0x0806),
            ofproto.OXM_OF_IPV6_SRC: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'eth_type',0x86dd),
            ofproto.OXM_OF_IPV6_DST: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'eth_type',0x86dd),
            ofproto.OXM_OF_IPV6_FLABEL: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'eth_type',0x86dd),
            ofproto.OXM_OF_ICMPV6_TYPE: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'ip_proto',58),
            ofproto.OXM_OF_ICMPV6_CODE: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'ip_proto',58),
            ofproto.OXM_OF_IPV6_ND_SLL: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'icmpv6_type',135),
            ofproto.OXM_OF_IPV6_ND_TLL: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'icmpv6_type',136),
            ofproto.OXM_OF_PBB_ISID: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'eth_type',0x88E7),
            ofproto.OXM_OF_IPV6_EXTHDR: lambda: add_prereq_match(self.flowSpecMatchDict[table_id],'eth_type',0x86dd)
        }
        
        for idx,field in enumerate(self.lookup_scope[table_id]):
            n_bits = ofproto_parser.OFPMatchField._FIELDS_HEADERS[field](field,0,0).oxm_len()*8
            # When calculating n_bits we are assuming symmetric fields in the two lookups (e.g. if lookup-scope has eth_src, then
            # update-scope would have eth_dst in the same position). Even in the unlikely case of completely unrelated fields,
            # we hope they are compatible at least having the same number of bits. This is true for sure for the total number
            # of bits, otherwise we would not be able to access the state table in read/write with keys of different lengths!!!
            src = ofproto_parser._NXFlowSpec._parse_subfield( bytearray(struct.pack('!IH',self.update_scope[table_id][idx],0)) )
            dst = ofproto_parser._NXFlowSpec._parse_subfield( bytearray(struct.pack('!IH',field,0)) )
            self.flowSpecMatchDict[table_id].add(NXHashableFlowSpecMatch(dst=dst,n_bits=n_bits,src=src))

            # This is a simple switch-case-equivalent block: if field=ofproto.OXM_OF_TCP_SRC, then the function
            # add_prereq_match(self.flowSpecMatchDict[table_id],'ip_proto',6) will be called and so a match ip_proto=6
            # will be added to learned flow entry.
            try:
                options[field]()
            except Exception:
                pass

        return self.flowSpecMatchDict[table_id]

    def generate_NXFlowSpecLoad(self,state,state_mask):
        ''' The new state to be loaded should be (old_state & ~state_mask)|(state & state_mask) '''
        import re
        if state_mask==0xffffffff:
            return [ofproto_parser.NXFlowSpecLoad(dst=('reg0',0),n_bits=32,src=state)]
        elif state_mask==0:
            return [ofproto_parser.NXFlowSpecLoad(dst=('reg0',0),n_bits=32,src=('reg0',0))]
        '''
        Example:
        state = 88 = 0b1011000
         mask = 92 = 0b1011100
        ovs-ofctl would produce "load:6->reg0[2..4],load:1->reg0[6]"
        NB: 2 and 4 are bit positions, starting from right (LSB)
        In this case we need to return [NXFlowSpecLoad(dst=('reg0',2),n_bits=3,src=6),NXFlowSpecLoad(dst=('reg0',6),n_bits=1,src=1)]
        '''
        flowSpecLoad = [ofproto_parser.NXFlowSpecLoad(dst=('reg0',0),n_bits=32,src=('reg0',0))]
        state_mask_str = '{0:032b}'.format(state_mask)
        groups, idxs = zip(*[(m.group(0), (m.start(), m.end()-1)) for m in re.finditer(r'1+', state_mask_str)])
        masked_state_str = '{0:032b}'.format(state&state_mask)

        for (s,e) in idxs:
            flowSpecLoad.append(ofproto_parser.NXFlowSpecLoad(dst=('reg0',31-e),n_bits=e-s+1,src=int(masked_state_str[s:e+1],2)))
        return flowSpecLoad

    def add_prereq_match_to_dict(self,lookup_scope,match):
        # OVS wrapper transforms a state table lookup into a flow table lookup, hence we need to observe match prerequisites:
        # for example, if lookup-scope contains OXM_OF_IPV4_SRC, we need a learn containing a NXFlowSpecMatch matching eth_type=0x800.
        def add_prereq_match(d,oxm_name,value):
            d[oxm_name]=value

        # This is the table 11 OF1.3 spec pag. 44
        ''' TODO: how can we handle pre-requisite such as OXM_OF_IP_DSCP with ETH TYPE=0x0800 or ETH TYPE=0x86dd ?? '''
        options = {
            ofproto.OXM_OF_IPV4_SRC: lambda: add_prereq_match(match,'eth_type',0x800),
            ofproto.OXM_OF_IPV4_DST: lambda: add_prereq_match(match,'eth_type',0x800),
            ofproto.OXM_OF_TCP_SRC: lambda: add_prereq_match(match,'ip_proto',6),
            ofproto.OXM_OF_TCP_DST: lambda: add_prereq_match(match,'ip_proto',6),
            ofproto.OXM_OF_UDP_SRC: lambda: add_prereq_match(match,'ip_proto',17),
            ofproto.OXM_OF_UDP_DST: lambda: add_prereq_match(match,'ip_proto',17),
            ofproto.OXM_OF_SCTP_SRC: lambda: add_prereq_match(match,'ip_proto',132),
            ofproto.OXM_OF_SCTP_DST: lambda: add_prereq_match(match,'ip_proto',132),
            ofproto.OXM_OF_ICMPV4_TYPE: lambda: add_prereq_match(match,'ip_proto',1),
            ofproto.OXM_OF_ICMPV4_CODE: lambda: add_prereq_match(match,'ip_proto',1),
            ofproto.OXM_OF_ARP_OP: lambda: add_prereq_match(match,'eth_type',0x0806),
            ofproto.OXM_OF_ARP_SPA: lambda: add_prereq_match(match,'eth_type',0x0806),
            ofproto.OXM_OF_ARP_TPA: lambda: add_prereq_match(match,'eth_type',0x0806),
            ofproto.OXM_OF_ARP_SHA: lambda: add_prereq_match(match,'eth_type',0x0806),
            ofproto.OXM_OF_ARP_THA: lambda: add_prereq_match(match,'eth_type',0x0806),
            ofproto.OXM_OF_IPV6_SRC: lambda: add_prereq_match(match,'eth_type',0x86dd),
            ofproto.OXM_OF_IPV6_DST: lambda: add_prereq_match(match,'eth_type',0x86dd),
            ofproto.OXM_OF_IPV6_FLABEL: lambda: add_prereq_match(match,'eth_type',0x86dd),
            ofproto.OXM_OF_ICMPV6_TYPE: lambda: add_prereq_match(match,'ip_proto',58),
            ofproto.OXM_OF_ICMPV6_CODE: lambda: add_prereq_match(match,'ip_proto',58),
            ofproto.OXM_OF_IPV6_ND_SLL: lambda: add_prereq_match(match,'icmpv6_type',135),
            ofproto.OXM_OF_IPV6_ND_TLL: lambda: add_prereq_match(match,'icmpv6_type',136),
            ofproto.OXM_OF_PBB_ISID: lambda: add_prereq_match(match,'eth_type',0x88E7),
            ofproto.OXM_OF_IPV6_EXTHDR: lambda: add_prereq_match(match,'eth_type',0x86dd)
        }

        for field in lookup_scope:           
            # This is a simple switch-case-equivalent block: if field=ofproto.OXM_OF_TCP_SRC, then the function
            # add_prereq_match(match,'ip_proto',6) will be called and so a match ip_proto=6 will be added to d
            try:
                options[field]()
            except Exception:
                pass

        return

    # OFP_EXP_STATE_MOD_SET_FLOW_STATE and OFP_EXP_STATE_MOD_DEL_FLOW_STATE sends keys as sequence of bytes.
    # We are building a standard OF match. For example if field is OXM_OF_ETH_SRC and field_value is [0,0,0,10,10,10], we should return "00:00:00:0a:0a:0a".
    def bytes_to_match_value(self,field,field_value):
        field_bytes_num = len(field_value)

        if field in [ofproto.OXM_OF_ETH_SRC,ofproto.OXM_OF_ETH_DST,ofproto.OXM_OF_ARP_SHA,ofproto.OXM_OF_ARP_THA,ofproto.OXM_OF_IPV6_ND_SLL,ofproto.OXM_OF_IPV6_ND_TLL]:
            return "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB",''.join([chr(x) for x in field_value]))
        elif field in [ofproto.OXM_OF_IPV4_SRC,ofproto.OXM_OF_IPV4_DST,ofproto.OXM_OF_ARP_SPA,ofproto.OXM_OF_ARP_TPA]:
            return "%d.%d.%d.%d" % tuple(field_value)
        elif field in [ofproto.OXM_OF_IPV6_SRC,ofproto.OXM_OF_IPV6_DST,ofproto.OXM_OF_IPV6_ND_TARGET]:
            ''' TODO: check '''
            return "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x" % struct.unpack("BBBBBBBBBBBBBBBB",''.join([chr(x) for x in field_value]))
        elif field_bytes_num==8:
            return struct.unpack('!Q',''.join([chr(x) for x in field_value]))[0]
        elif field_bytes_num==4:
            return struct.unpack('!I',''.join([chr(x) for x in field_value]))[0]
        elif field_bytes_num==2:
            return struct.unpack('!H',''.join([chr(x) for x in field_value]))[0]
        elif field_bytes_num==1:
            return struct.unpack('!B',''.join([chr(x) for x in field_value]))[0]

'''
By decorating 'switch_features_handler()' with '@Beba2OVSWrapper', before the execution of the user-defined switch_features_handler()
the decorator obtains the Datapath instance 'datapath', casts it to an OVSDatapath object and initializes lookup_scope and update_scope dict.
Finally it executes the user-defined switch_features_handler().
NB: The 'datapath' instance returned to the handler of any subsequent events (e.g. packet_in_handler) is the same, so even if
the 2 scopes dict have been configured by an OFPExpMsgKeyExtract in a previous event handler, they are still available to
transform an OFPExpActionSetState in a NXActionLearn.
'''
def Beba2OVSWrapper(function):
    def inner(self, ev):
        datapath = ev.msg.datapath
        datapath.__class__ = OVSDatapath
        datapath.lookup_scope = {}
        datapath.update_scope = {}
        datapath.flowSpecMatchDict = {}
        datapath.stateful_stages_in_use = Set([])
        return function(self, ev)
    return inner
