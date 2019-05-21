#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "openflow/openflow.h"
#include "openflow/beba-ext.h"
#include "ofl-exp-beba.h"
#include "oflib/ofl-log.h"
#include "oflib/ofl-print.h"
#include "oflib/ofl-utils.h"
#include "oflib/ofl-structs.h"
#include "oflib/oxm-match.h"
#include "lib/hash.h"
#include "lib/ofp.h"
#include "lib/ofpbuf.h"
#include "timeval.h"
#include "oflib/ofl.h"


#define LOG_MODULE ofl_exp_os
OFL_LOG_INIT(LOG_MODULE)

bool soft_decap_parsing = false;

bool get_soft_flag();

void set_soft_flag(bool flag);

/* functions used  by ofp_exp_msg_pkttmp_mod */
static ofl_err
ofl_structs_add_pkttmp_unpack(struct ofp_exp_add_pkttmp const *src, size_t *len, struct ofl_exp_add_pkttmp *dst) {
    //int i;
    //uint8_t key[OFPSC_MAX_KEY_LEN] = {0};
    uint8_t *data = NULL;

    if( *len >= sizeof(struct ofp_exp_add_pkttmp) )
    {
        OFL_LOG_DBG(LOG_MODULE, "Received PKTTMP_MOD message to set pkttmp_id (%"PRIu32") [Msg_len: %zu].", src->pkttmp_id, *len);
        dst->pkttmp_id = ntohl(src->pkttmp_id);

        *len -= sizeof(struct ofp_exp_add_pkttmp);
        data = ((uint8_t *)src) + sizeof(struct ofp_exp_add_pkttmp);

        dst->data_length = *len;
        dst->data = *len > 0 ? (uint8_t *)memcpy(malloc(*len), data, *len) : NULL;
        *len = 0;
    }
    else
    { //control of struct ofp_extraction length.
       OFL_LOG_WARN(LOG_MODULE, "Received pkttmp mod add_pkttmp is too short (%zu).", *len);
       return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    return 0;
}

static ofl_err
ofl_structs_del_pkttmp_unpack(struct ofp_exp_del_pkttmp const *src, size_t *len, struct ofl_exp_del_pkttmp *dst) {
    //int i;
    //uint8_t key[OFPSC_MAX_KEY_LEN] = {0};

    if( *len == sizeof(struct ofp_exp_del_pkttmp) )
    {
        OFL_LOG_DBG(LOG_MODULE, "NOT IMPLEMENTED! Received PKTTMP_MOD message to delete pkttmp_id (%"PRIu32").", src->pkttmp_id );
        dst->pkttmp_id = ntohl(src->pkttmp_id);
    }
    else
    { //control of struct ofp_extraction length.
       OFL_LOG_WARN(LOG_MODULE, "Received pkttmp mod del_pkttmp is too short (%zu).", *len);
       return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= (sizeof(struct ofp_exp_del_pkttmp));

    return 0;
}

/* functions used by ofp_exp_msg_state_mod*/
static ofl_err
ofl_structs_stateful_table_config_unpack(struct ofp_exp_stateful_table_config const *src, size_t *len, struct ofl_exp_stateful_table_config *dst)
{
    if(*len == sizeof(struct ofp_exp_stateful_table_config))
    {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%d).", src->table_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
        }
        dst->table_id = src->table_id;
        dst->stateful = src->stateful;
    }
    else
    {
       OFL_LOG_WARN(LOG_MODULE, "Received state mod stateful_table_config is too short (%zu).", *len);
       return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= sizeof(struct ofp_exp_stateful_table_config);

    return 0;
}

static ofl_err
ofl_structs_extraction_unpack(struct ofp_exp_set_extractor const *src, size_t *len, struct ofl_exp_set_extractor *dst)
{
    int i;
    if(*len == ((1+ntohl(src->field_count))*sizeof(uint32_t) + 4*sizeof(uint8_t) + 4*sizeof(uint8_t)) && (ntohl(src->field_count)>0))
    {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%d).", src->table_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
        }
        dst->table_id = src->table_id;
        dst->field_count=ntohl(src->field_count);
        dst->biflow = src->biflow;
        dst->bit = src->bit;
        for (i=0;i<dst->field_count;i++)
        {
            dst->fields[i]=ntohl(src->fields[i]);
        }
    }
    else
    { //check of struct ofp_exp_set_extractor length.
       OFL_LOG_WARN(LOG_MODULE, "Received state mod extraction is too short (%zu).", *len);
       return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= (((1+ntohl(src->field_count))*sizeof(uint32_t)) + 4*sizeof(uint8_t) + 4*sizeof(uint8_t));

    return 0;
}

static ofl_err
ofl_structs_set_flow_state_unpack(struct ofp_exp_set_flow_state const *src, size_t *len, struct ofl_exp_set_flow_state *dst)
{
    int i;
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};

    if((*len == ((7*sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t))) + 4*sizeof(uint8_t)) && (ntohl(src->key_len)>0))
    {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%d).", src->table_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
        }
        dst->table_id = src->table_id;
        dst->key_len=ntohl(src->key_len);
        dst->state=ntohl(src->state);
        dst->state_mask=ntohl(src->state_mask);
        dst->idle_timeout = ntohl(src->idle_timeout);
        dst->idle_rollback = ntohl(src->idle_rollback);
        dst->hard_timeout = ntohl(src->hard_timeout);
        dst->hard_rollback = ntohl(src->hard_rollback);
        for (i=0;i<dst->key_len;i++)
            key[i]=src->key[i];
        memcpy(dst->key, key, dst->key_len);
    }
    else
    { //check of struct ofp_exp_set_flow_state length.
       OFL_LOG_WARN(LOG_MODULE, "Received state mod set_flow is too short (%zu).", *len);
       return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= ((7*sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t)) + 4*sizeof(uint8_t));

    return 0;
}

static ofl_err
ofl_structs_del_flow_state_unpack(struct ofp_exp_del_flow_state const *src, size_t *len, struct ofl_exp_del_flow_state *dst)
{
    int i;
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};

    if((*len == ((sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t))) + 4*sizeof(uint8_t)) && (ntohl(src->key_len)>0))
    {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%d).", src->table_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
        }
        dst->table_id = src->table_id;
        dst->key_len=ntohl(src->key_len);
        for (i=0;i<dst->key_len;i++)
            key[i]=src->key[i];
        memcpy(dst->key, key, dst->key_len);
        OFL_LOG_DBG(LOG_MODULE, "key count is %d\n",dst->key_len);
    }
    else
    { //check of struct ofp_exp_del_flow_state length.
       OFL_LOG_WARN(LOG_MODULE, "Received state mod del_flow is too short (%zu).", *len);
       return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= ((sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t)) + 4*sizeof(uint8_t));

    return 0;
}

static ofl_err
ofl_structs_set_global_state_unpack(struct ofp_exp_set_global_state const *src, size_t *len, struct ofl_exp_set_global_state *dst)
{

    if (*len == 2*sizeof(uint32_t)) {
        dst->global_state = ntohl(src->global_state);
        dst->global_state_mask = ntohl(src->global_state_mask);
    }
    else {
        //check of struct ofp_exp_set_global_state length.
        OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD set global state has invalid length (%zu).", *len);
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= sizeof(struct ofp_exp_set_global_state);

    return 0;
}

static ofl_err
ofl_structs_set_header_field_unpack(struct ofp_exp_set_header_field_extractor const *src, size_t *len, struct ofl_exp_set_header_field_extractor *dst) {

    if(*len == sizeof(struct ofp_exp_set_header_field_extractor)){
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%u).", src->table_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
        }
        if (src->extractor_id >= OFPSC_MAX_HEADER_FIELDS) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid extractor id (%u).", src->extractor_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXTRACTOR_ID);
        }
        // Header field extractor should be a field <=32 bit. Bigger header fields are now admitted, but data is truncated to 32 bit.
        /* if ((OXM_VENDOR(ntohl(src->field))==0xFFFF && OXM_LENGTH(ntohl(src->field))-EXP_ID_LEN > 4) || (OXM_VENDOR(ntohl(src->field))!=0xFFFF && OXM_LENGTH(ntohl(src->field)) > 4)) {
               OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid header field size (%u).", OXM_LENGTH(ntohl(src->field)));
               return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_HEADER_FIELD_SIZE);
         } */

        dst->table_id = src->table_id;
        dst->extractor_id = src->extractor_id;
        dst->field = ntohl(src->field);
    }
    else {
        //check of struct ofp_exp_set_header_field_extractor length.
        OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD set_header_field has invalid length (%zu).", *len);
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= sizeof(struct ofp_exp_set_header_field_extractor);

    return 0;
}

ofl_err
ofl_structs_set_condition_unpack(struct ofp_exp_set_condition const *src, size_t *len, struct ofl_exp_set_condition *dst) {
    ofl_err error;

    if(*len == sizeof(struct ofp_exp_set_condition)) {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%u).", src->table_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
        }

        if (src->condition_id >= OFPSC_MAX_CONDITIONS_NUM) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid condition id (%u).", src->condition_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_CONDITION_ID);
        }

        if (src->condition > 5) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid condition (%u).", src->condition );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_CONDITION);
        }

        // operand_types=xxyy0000 where xx=operand_1_type and yy=operand_2_type

        // operand_1 can be FLOW_DATA_VAR, GLOBAL_DATA_VAR or HEADER_FIELD
        error = check_operands((src->operand_types>>6)&3,src->operand_1,"operand_1",false,true);
        if (error)
            return error;

        // operand_2 can be FLOW_DATA_VAR, GLOBAL_DATA_VAR or HEADER_FIELD
        error = check_operands((src->operand_types>>4)&3,src->operand_2,"operand_2",false,true);
        if (error)
            return error;

        dst->table_id = src->table_id;
        dst->condition_id = src->condition_id;
        dst->condition = src->condition;
        dst->operand_types = src->operand_types;
        dst->operand_1 = src->operand_1;
        dst->operand_2 = src->operand_2;

    }
    else {
        //check of struct ofp_exp_set_condition length.
        OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD set_condition has invalid length (%zu).", *len);
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= sizeof(struct ofp_exp_set_condition);

    return 0;
}

ofl_err
ofl_structs_set_global_data_var_unpack(struct ofp_exp_set_global_data_variable const *src, size_t *len, struct ofl_exp_set_global_data_variable *dst) {

    if(*len == sizeof(struct ofp_exp_set_global_data_variable)) {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%u).", src->table_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
        }
        if (src->global_data_variable_id >= OFPSC_MAX_GLOBAL_DATA_VAR_NUM){
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid global data variable id (%u).", src->global_data_variable_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_GLOBAL_DATA_VAR_ID);
        }
        dst->table_id = src->table_id;
        dst->global_data_variable_id = src->global_data_variable_id;
        dst->value=ntohl(src->value);
        dst->mask=ntohl(src->mask);
    }
    else {
        //check of struct ofp_exp_set_global_data_variable length.
        OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD set_global_data_var has invalid length (%zu).", *len);
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= sizeof(struct ofp_exp_set_global_data_variable);

    return 0;
}

ofl_err
ofl_structs_set_flow_data_var_unpack(struct ofp_exp_set_flow_data_variable const *src, size_t *len, struct ofl_exp_set_flow_data_variable *dst) {
    int i;
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};

    if((*len == ((4*sizeof(uint8_t) + 3*sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t)))) && (ntohl(src->key_len)>0)){
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%u).", src->table_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
        }
        if (src->flow_data_variable_id >= OFPSC_MAX_FLOW_DATA_VAR_NUM){
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid FLOW data variable id (%u).", src->flow_data_variable_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_FLOW_DATA_VAR_ID);
        }

        dst->table_id = src->table_id;
        dst->flow_data_variable_id = src->flow_data_variable_id;
        dst->value=ntohl(src->value);
        dst->mask=ntohl(src->mask);
        dst->key_len=ntohl(src->key_len);
        for (i=0;i<dst->key_len;i++)
            key[i]=src->key[i];
        memcpy(dst->key, key, dst->key_len);
    }
    else {
        //check of struct ofp_exp_set_flow_data_variable length.
        OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD set_flow_data_var is too short (%zu).", *len);
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= ((4*sizeof(uint8_t) + 3*sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t)));

    return 0;
}

int
ofl_exp_beba_msg_pack(struct ofl_msg_experimenter const *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp const *exp UNUSED)
{
    struct ofl_exp_beba_msg_header *exp_msg = (struct ofl_exp_beba_msg_header *)msg;
    switch (exp_msg->type) {
       /* State Sync: Pack the state change message */
       case(OFPT_EXP_STATE_CHANGED): {
           struct ofl_exp_msg_notify_state_change *ntf = (struct ofl_exp_msg_notify_state_change *) exp_msg;
           struct ofp_exp_msg_state_ntf *ntf_msg;

           *buf_len = sizeof(struct ofp_experimenter_header) + 5*sizeof(uint32_t) + ntf->key_len*sizeof(uint8_t) + OFPSC_MAX_FLOW_DATA_VAR_NUM * sizeof(uint32_t); //sizeof(struct ofp_exp_msg_state_ntf);
           *buf     = (uint8_t *)malloc(*buf_len);

           ntf_msg = (struct ofp_exp_msg_state_ntf *)(*buf);

           ntf_msg->header.experimenter = htonl(BEBA_VENDOR_ID);
           ntf_msg->header.exp_type = htonl(OFPT_EXP_STATE_CHANGED);
           ntf_msg->table_id = htonl(ntf->table_id);
           ntf_msg->old_state = htonl(ntf->old_state);
           ntf_msg->new_state = htonl(ntf->new_state);
           ntf_msg->state_mask = htonl(ntf->state_mask);
           ntf_msg->key_len = htonl(ntf->key_len);
           memcpy(ntf_msg->key, ntf->key, ntf->key_len);
           memcpy(ntf_msg->flow_data_var, ntf->flow_data_var, OFPSC_MAX_FLOW_DATA_VAR_NUM * sizeof(uint32_t));
           return 0;
        }
        /* State Sync: Pack positive flow modification acknowledgment. */
        case (OFPT_EXP_FLOW_NOTIFICATION) :
        {
            struct ofl_exp_msg_notify_flow_change *ntf = (struct ofl_exp_msg_notify_flow_change *)exp_msg;
            struct ofp_exp_msg_flow_ntf * ntf_msg;

            uint8_t * ptr;
            uint32_t * data;
            int i;

            *buf_len = ROUND_UP(sizeof(struct ofp_exp_msg_flow_ntf)-4 + ntf->match->length,8) +
                      ROUND_UP((ntf->instruction_num+1)*sizeof(uint32_t),8);
            *buf     = (uint8_t *)malloc(*buf_len);

            ntf_msg = (struct ofp_exp_msg_flow_ntf *)(*buf);

            ntf_msg->header.experimenter = htonl(BEBA_VENDOR_ID);
            ntf_msg->header.exp_type = htonl(OFPT_EXP_FLOW_NOTIFICATION);
            ntf_msg->table_id = htonl(ntf->table_id);
            ntf_msg->ntf_type = htonl(ntf->ntf_type);

            ptr = *buf + sizeof(struct ofp_exp_msg_flow_ntf)-4;
            ofl_structs_match_pack(ntf->match, &(ntf_msg->match),ptr, exp);

            data = (uint32_t *)(*buf + ROUND_UP(sizeof(struct ofp_exp_msg_flow_ntf)-4+ntf->match->length,8));
            *data = htonl(ntf->instruction_num);
            //NB: instructions are not full 'struct ofp_instruction'. We send back to the ctrl just a list of instruction types

            ++data;
            for (i=0;i<ntf->instruction_num;++i){
               *data = htonl(ntf->instructions[i]);
               ++data;
            }
            return 0;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown Beba Experimenter message.");
            return -1;
        }
    }
}

ofl_err
check_operands(uint8_t operand_type, uint8_t operand_value, char * operand_name, bool allow_constant, bool allow_header_field) {
    switch (operand_type){
        case OPERAND_TYPE_FLOW_DATA_VAR:
            if (operand_value >= OFPSC_MAX_FLOW_DATA_VAR_NUM){
                OFL_LOG_WARN(LOG_MODULE, "Received SET DATA VAR action has invalid flow data variable id (%s) (%u).", operand_name, operand_value);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_FLOW_DATA_VAR_ID);
            }
            OFL_LOG_DBG(LOG_MODULE, "Received SET DATA VAR action with OPERAND_TYPE_FLOW_DATA_VAR %s", operand_name);
            break;
        case OPERAND_TYPE_GLOBAL_DATA_VAR:
            if (operand_value >= OFPSC_MAX_GLOBAL_DATA_VAR_NUM){
                OFL_LOG_WARN(LOG_MODULE, "Received SET DATA VAR action has invalid global data variable id (%s) (%u).", operand_name, operand_value);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_GLOBAL_DATA_VAR_ID);
            }
            OFL_LOG_DBG(LOG_MODULE, "Received SET DATA VAR action with OPERAND_TYPE_GLOBAL_DATA_VAR %s", operand_name);
            break;
        case OPERAND_TYPE_HEADER_FIELD:
            if (allow_header_field){
                if (operand_value >= OFPSC_MAX_HEADER_FIELDS) {
                    OFL_LOG_WARN(LOG_MODULE, "Received SET DATA VAR action has invalid extractor id (%s) (%u).", operand_name, operand_value);
                    return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXTRACTOR_ID);
                }
                OFL_LOG_DBG(LOG_MODULE, "Received SET DATA VAR action with OPERAND_TYPE_HEADER_FIELD %s", operand_name);
            } else {
                OFL_LOG_WARN(LOG_MODULE, "Received SET DATA VAR action has invalid %s type (%u).", operand_name, operand_value);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_OPERAND_TYPE);
            }
            break;
        case OPERAND_TYPE_CONSTANT:
            if (allow_constant){
                OFL_LOG_DBG(LOG_MODULE, "Received SET DATA VAR action with OPERAND_TYPE_CONSTANT %s", operand_name);
            } else {
                OFL_LOG_WARN(LOG_MODULE, "Received SET DATA VAR action has invalid %s type (%u).", operand_name, operand_value);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_OPERAND_TYPE);
            }
            break;
        default:
            OFL_LOG_WARN(LOG_MODULE, "Received SET DATA VAR action has invalid %s type (%u).", operand_name, operand_value);
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_OPERAND_TYPE);
    }

    return 0;
}

ofl_err
ofl_exp_beba_msg_unpack(struct ofp_header const *oh, size_t *len, struct ofl_msg_experimenter **msg, struct ofl_exp const *exp)
{
    struct ofp_experimenter_header *exp_header;

    if (*len < sizeof(struct ofp_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message has invalid length (%zu).", *len);
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    exp_header = (struct ofp_experimenter_header *)oh;

    switch (ntohl(exp_header->exp_type)) {
        case (OFPT_EXP_STATE_MOD):
        {
            struct ofp_exp_msg_state_mod *sm;
            struct ofl_exp_msg_state_mod *dm;

            *len -= sizeof(struct ofp_experimenter_header);

            sm = (struct ofp_exp_msg_state_mod *)exp_header;
            dm = (struct ofl_exp_msg_state_mod *)malloc(sizeof(struct ofl_exp_msg_state_mod));

            dm->header.header.experimenter_id = ntohl(exp_header->experimenter);
            dm->header.type                   = ntohl(exp_header->exp_type);

            (*msg) = (struct ofl_msg_experimenter *)dm;

            /*2*sizeof(uint8_t) = enum ofp_exp_msg_state_mod_commands + 1 byte of padding*/
            if (*len < 2*sizeof(uint8_t)) {
                OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            dm->command = (enum ofp_exp_msg_state_mod_commands)sm->command;

            *len -= 2*sizeof(uint8_t);

            switch(dm->command){
                case OFPSC_STATEFUL_TABLE_CONFIG:
                    return ofl_structs_stateful_table_config_unpack((struct ofp_exp_stateful_table_config const *)&(sm->payload[0]), len,
                                                               (struct ofl_exp_stateful_table_config *)&(dm->payload[0]));
                case OFPSC_EXP_SET_L_EXTRACTOR:
                case OFPSC_EXP_SET_U_EXTRACTOR:
                    return ofl_structs_extraction_unpack((struct ofp_exp_set_extractor const *)&(sm->payload[0]), len,
                                                    (struct ofl_exp_set_extractor *)&(dm->payload[0]));
                case OFPSC_EXP_SET_FLOW_STATE:
                    return ofl_structs_set_flow_state_unpack((struct ofp_exp_set_flow_state const *)&(sm->payload[0]), len,
                                                    (struct ofl_exp_set_flow_state *)&(dm->payload[0]));
                case OFPSC_EXP_DEL_FLOW_STATE:
                    return ofl_structs_del_flow_state_unpack((struct ofp_exp_del_flow_state const *)&(sm->payload[0]), len,
                                                    (struct ofl_exp_del_flow_state *)&(dm->payload[0]));
                case OFPSC_EXP_SET_GLOBAL_STATE:
                    return ofl_structs_set_global_state_unpack((struct ofp_exp_set_global_state const *)&(sm->payload[0]), len,
                                                    (struct ofl_exp_set_global_state *)&(dm->payload[0]));
                case OFPSC_EXP_SET_HEADER_FIELD_EXTRACTOR:
                    return ofl_structs_set_header_field_unpack((struct ofp_exp_set_header_field_extractor const *)&(sm->payload[0]), len,
                                                    (struct ofl_exp_set_header_field_extractor *)&(dm->payload[0]));
                case OFPSC_EXP_SET_CONDITION:
                    return ofl_structs_set_condition_unpack((struct ofp_exp_set_condition const *)&(sm->payload[0]), len,
                                                    (struct ofl_exp_set_condition *)&(dm->payload[0]));
                case OFPSC_EXP_SET_GLOBAL_DATA_VAR:
                    return ofl_structs_set_global_data_var_unpack((struct ofp_exp_set_global_data_variable const *)&(sm->payload[0]), len,
                                                    (struct ofl_exp_set_global_data_variable *)&(dm->payload[0]));
                case OFPSC_EXP_SET_FLOW_DATA_VAR:
                    return ofl_structs_set_flow_data_var_unpack((struct ofp_exp_set_flow_data_variable const *)&(sm->payload[0]), len,
                                                    (struct ofl_exp_set_flow_data_variable *)&(dm->payload[0]));
                default:
                    return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_STATE_MOD_BAD_COMMAND);
            }
        }
        case (OFPT_EXP_PKTTMP_MOD):
        {
            struct ofp_exp_msg_pkttmp_mod *sm;
            struct ofl_exp_msg_pkttmp_mod *dm;

            *len -= sizeof(struct ofp_experimenter_header);

            sm = (struct ofp_exp_msg_pkttmp_mod *)exp_header;
            dm = (struct ofl_exp_msg_pkttmp_mod *)malloc(sizeof(struct ofl_exp_msg_pkttmp_mod));

            dm->header.header.experimenter_id = ntohl(exp_header->experimenter);
            dm->header.type                   = ntohl(exp_header->exp_type);

            (*msg) = (struct ofl_msg_experimenter *)dm;

            if (*len < 2*sizeof(uint8_t)) {
                OFL_LOG_WARN(LOG_MODULE, "Received PKTTMP_MOD message has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            dm->command = (enum ofp_exp_msg_pkttmp_mod_commands)sm->command;

            *len -= 2*sizeof(uint8_t);

            switch(dm->command){
                case OFPSC_ADD_PKTTMP:
                    return ofl_structs_add_pkttmp_unpack((struct ofp_exp_add_pkttmp const *)&(sm->payload[0]), len, (struct ofl_exp_add_pkttmp *)&(dm->payload[0]));
                case OFPSC_DEL_PKTTMP:
                    return ofl_structs_del_pkttmp_unpack((struct ofp_exp_del_pkttmp const *)&(sm->payload[0]), len, (struct ofl_exp_del_pkttmp *)&(dm->payload[0]));
                default:
                    return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_PKTTMP_MOD_BAD_COMMAND);
            }
        }
        case (OFPT_EXP_STATE_CHANGED):
        {
            struct ofp_exp_msg_state_ntf *sm;
            struct ofl_exp_msg_notify_state_change *dm;

            *len -= sizeof(struct ofp_experimenter_header);

            sm = (struct ofp_exp_msg_state_ntf *)exp_header;
            dm = (struct ofl_exp_msg_notify_state_change *)malloc(sizeof(struct ofl_exp_msg_notify_state_change));

            dm->header.header.experimenter_id = ntohl(exp_header->experimenter);
            dm->header.type                   = ntohl(exp_header->exp_type);

            (*msg) = (struct ofl_msg_experimenter *)dm;

            if (*len < 5*sizeof(uint32_t)) {
                OFL_LOG_WARN(LOG_MODULE, "Received OFPT_EXP_STATE_CHANGED message has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            dm->table_id = ntohl(sm->table_id);
            dm->old_state = ntohl(sm->old_state);
            dm->new_state = ntohl(sm->new_state);
            dm->state_mask = ntohl(sm->state_mask);
            dm->key_len = ntohl(sm->key_len);
            memcpy(dm->key, sm->key, dm->key_len);
            memcpy(dm->flow_data_var, sm->flow_data_var, OFPSC_MAX_FLOW_DATA_VAR_NUM * sizeof(uint32_t));
            *len -= 5*sizeof(uint32_t) + dm->key_len*sizeof(uint8_t) + OFPSC_MAX_FLOW_DATA_VAR_NUM * sizeof(uint32_t);
            return 0;
        }
        case (OFPT_EXP_FLOW_NOTIFICATION):
        {
            struct ofp_exp_msg_flow_ntf * sm;
            struct ofl_exp_msg_notify_flow_change *dm;
            uint32_t * data;
            int i;
            ofl_err error;

            sm = (struct ofp_exp_msg_flow_ntf *)exp_header;
            dm = (struct ofl_exp_msg_notify_flow_change *) malloc(sizeof(struct ofl_exp_msg_notify_flow_change));

            dm->header.header.experimenter_id = ntohl(exp_header->experimenter);
            dm->header.type = ntohl(exp_header->exp_type);

            *msg = (struct ofl_msg_experimenter *)dm;

            dm->table_id = ntohl(sm->table_id);
            dm->ntf_type = ntohl(sm->ntf_type);

            *len -= ((sizeof(struct ofp_exp_msg_flow_ntf)) - sizeof(struct ofp_match));
            error = ofl_structs_match_unpack(&(sm->match), ((uint8_t *)oh)+sizeof(struct ofp_exp_msg_flow_ntf)-4, len, &(dm->match), 0, exp);

            if (error) {
                ofl_structs_free_match(dm->match, NULL);
                free(dm);
                return error;
            }

            data = (uint32_t * )(((uint8_t *)oh) + ROUND_UP(sizeof(struct ofp_exp_msg_flow_ntf)-4 + dm->match->length, 8));
            //NB: instructions are not full 'struct ofp_instruction'. We send back to the ctrl just a list of instruction types
            dm->instruction_num = ntohl(*data);

            if (dm->instruction_num>0) {
                dm->instructions = malloc(dm->instruction_num*sizeof(uint32_t));
                data++;
                for(i=0; i<(dm->instruction_num); i++){
                    dm->instructions[i] = ntohl(*data);
                    data++;
                }
             } else {
                dm->instructions = NULL;
            }

            *len -= ROUND_UP((dm->instruction_num+1)* sizeof(uint32_t), 8);

            return 0;
        }
        default: {
            struct ofl_msg_experimenter *dm;
            dm = (struct ofl_msg_experimenter *)malloc(sizeof(struct ofl_msg_experimenter));
            dm->experimenter_id = ntohl(exp_header->experimenter);
            (*msg) = dm;
            OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown Beba Experimenter message.");
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_MESSAGE);
        }
    }
}

int
ofl_exp_beba_msg_free(struct ofl_msg_experimenter *msg)
{
    struct ofl_exp_beba_msg_header *exp = (struct ofl_exp_beba_msg_header *)msg;
    switch (exp->type) {
        case (OFPT_EXP_STATE_MOD):
        {
            struct ofl_exp_msg_state_mod *state_mod = (struct ofl_exp_msg_state_mod *)exp;
            OFL_LOG_DBG(LOG_MODULE, "Free Beba STATE_MOD Experimenter message. bebaexp{type=\"%u\", command=\"%u\"}", exp->type, state_mod->command);
            free(msg);
            break;
        }
        case (OFPT_EXP_PKTTMP_MOD):
        {
            struct ofl_exp_msg_pkttmp_mod *pkttmp_mod = (struct ofl_exp_msg_pkttmp_mod *)exp;
            OFL_LOG_DBG(LOG_MODULE, "Free Beba PKTTMP_MOD Experimenter message. bebaexp{type=\"%u\", command=\"%u\"}", exp->type, pkttmp_mod->command);
            free(msg);
            break;
        }
        case (OFPT_EXP_STATE_CHANGED):
        {
            OFL_LOG_DBG(LOG_MODULE, "Free Beba OFPT_EXP_STATE_CHANGED Experimenter message. bebaexp{type=\"%u\"}", exp->type);
            free(msg);
            break;
        }
        case (OFPT_EXP_FLOW_NOTIFICATION):
        {
            struct ofl_exp_msg_notify_flow_change * msg = (struct ofl_exp_msg_notify_flow_change *) exp;
            OFL_LOG_DBG(LOG_MODULE, "Free Beba FLOW_NOTIFICATION Experimenter message. bebaexp{type=\"%u\", table_id=\"%u\"}", exp->type, msg->table_id);
            ofl_structs_free_match(msg->match,NULL);
            if (msg->instruction_num>0 && msg->instructions!=NULL){
                free(msg->instructions);
            }
            free(msg);
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Beba Experimenter message.");
        }
    }
    return 0;
}

char *
ofl_exp_beba_msg_to_string(struct ofl_msg_experimenter const *msg, struct ofl_exp const *exp)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    struct ofl_exp_beba_msg_header *exp_msg = (struct ofl_exp_beba_msg_header *)msg;
    switch (exp_msg->type) {
        case (OFPT_EXP_STATE_MOD):
        {
            struct ofl_exp_msg_state_mod *state_mod = (struct ofl_exp_msg_state_mod *)exp_msg;
            OFL_LOG_DBG(LOG_MODULE, "Print Beba STATE_MOD Experimenter message BEBA_MSG{type=\"%u\", command=\"%u\"}", exp_msg->type, state_mod->command);
            break;
        }
        case (OFPT_EXP_PKTTMP_MOD):
        {
            struct ofl_exp_msg_pkttmp_mod *pkttmp_mod = (struct ofl_exp_msg_pkttmp_mod *)exp_msg;
            OFL_LOG_DBG(LOG_MODULE, "Print Beba PKTTMP_MOD Experimenter message BEBA_MSG{type=\"%u\", command=\"%u\"}", exp_msg->type, pkttmp_mod->command);
            break;
        }
        case (OFPT_EXP_STATE_CHANGED):
        {
            OFL_LOG_DBG(LOG_MODULE, "Print Beba OFPT_EXP_STATE_CHANGED Experimenter message BEBA_MSG{type=\"%u\"}", exp_msg->type);
            break;
        }
        case (OFPT_EXP_FLOW_NOTIFICATION):{
            struct ofl_exp_msg_notify_flow_change * msg = (struct ofl_exp_msg_notify_flow_change *) exp_msg;
            int i;
            char *s;

            s = ofl_structs_match_to_string(msg->match, exp);
            OFL_LOG_DBG(LOG_MODULE, "Flow modification confirmed, flow table: \"%u\" , match fields \"%s\" ", msg->table_id, s);
            free(s);
            OFL_LOG_DBG(LOG_MODULE, "Instructions : ");
            for(i=0; i<msg->instruction_num; i++){
                s = ofl_instruction_type_to_string(msg->instructions[i]);
                OFL_LOG_DBG(LOG_MODULE, "  \"%s\"  ", s);
                free(s);
            }
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown Beba Experimenter message UNKN_BEBA_MSG{type=\"%u\"}", exp_msg->type);
            break;
        }
    }
    fclose(stream);
    return str;
}

/*experimenter action functions*/

ofl_err
ofl_exp_beba_act_unpack(struct ofp_action_header const *src, size_t *len, struct ofl_action_header **dst)
{
    struct ofp_action_experimenter_header const *exp;
    struct ofp_beba_action_experimenter_header const *ext;
    int i=0;
    ofl_err error;

    if (*len < sizeof(struct ofp_action_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp = (struct ofp_action_experimenter_header const *)src;
    ext = (struct ofp_beba_action_experimenter_header const *)exp;

    switch (ntohl(ext->act_type)) {
        case (OFPAT_EXP_SET_STATE):
        {
            // At unpack time we do NOT check if stage is stateful and state table is configured: those checks are run at action execution time
            struct ofp_exp_action_set_state *sa;
            struct ofl_exp_action_set_state *da;

            sa = (struct ofp_exp_action_set_state *)ext;
            da = (struct ofl_exp_action_set_state *)malloc(sizeof(struct ofl_exp_action_set_state));
            da->header.header.experimenter_id = ntohl(exp->experimenter);
            da->header.act_type = ntohl(ext->act_type);
            *dst = (struct ofl_action_header *)da;

            if (*len < sizeof(struct ofp_exp_action_set_state) + ROUND_UP(sizeof(uint32_t)*(ntohl(sa->field_count)),8) ) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET STATE action has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            if (sa->table_id >= PIPELINE_TABLES) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *ts = ofl_table_to_string(sa->table_id);
                    OFL_LOG_WARN(LOG_MODULE, "Received SET STATE action has invalid table_id (%s).", ts);
                    free(ts);
                }
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
            }

            da->state = ntohl(sa->state);
            da->state_mask = ntohl(sa->state_mask);
            da->table_id = sa->table_id;
            da->hard_rollback = ntohl(sa->hard_rollback);
            da->idle_rollback = ntohl(sa->idle_rollback);
            da->hard_timeout = ntohl(sa->hard_timeout);
            da->idle_timeout = ntohl(sa->idle_timeout);
            da->bit = sa->bit;
            da->field_count=ntohl(sa->field_count);

            for (i=0;i<da->field_count;i++)
                da->fields[i]=ntohl(sa->fields[i]);
            
            *len -= sizeof(struct ofp_exp_action_set_state) + ROUND_UP(sizeof(uint32_t)*(da->field_count),8);
            break;
        }

        case (OFPAT_EXP_SET_GLOBAL_STATE):
        {
            struct ofp_exp_action_set_global_state *sa;
            struct ofl_exp_action_set_global_state *da;
            sa = (struct ofp_exp_action_set_global_state*)ext;
            da = (struct ofl_exp_action_set_global_state *)malloc(sizeof(struct ofl_exp_action_set_global_state));

            da->header.header.experimenter_id = ntohl(exp->experimenter);
            da->header.act_type = ntohl(ext->act_type);

            *dst = (struct ofl_action_header *)da;
            if (*len < sizeof(struct ofp_exp_action_set_global_state)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET GLOBAL STATE action has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            da->global_state = ntohl(sa->global_state);
            da->global_state_mask = ntohl(sa->global_state_mask);

            *len -= sizeof(struct ofp_exp_action_set_global_state);
            break;
        }

        case (OFPAT_EXP_INC_STATE):
        {
            struct ofp_exp_action_inc_state *sa;
            struct ofl_exp_action_inc_state *da;
            sa = (struct ofp_exp_action_inc_state*)ext;
            da = (struct ofl_exp_action_inc_state *)malloc(sizeof(struct ofl_exp_action_inc_state));

            da->header.header.experimenter_id = ntohl(exp->experimenter);
            da->header.act_type = ntohl(ext->act_type);

            *dst = (struct ofl_action_header *)da;
            if (*len < sizeof(struct ofp_exp_action_inc_state)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET INC STATE action has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            if (sa->table_id >= PIPELINE_TABLES) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *ts = ofl_table_to_string(sa->table_id);
                    OFL_LOG_WARN(LOG_MODULE, "Received SET INC STATE action has invalid table_id (%s).", ts);
                    free(ts);
                }
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
            }

            da->table_id = sa->table_id;

            *len -= sizeof(struct ofp_exp_action_inc_state);
            break;
        }
        
        case (OFPAT_EXP_SET_DATA_VAR):
        {
            // At unpack time we do NOT check if stage is stateful and state table is configured: those checks are run at action execution time
            struct ofp_exp_action_set_data_variable *sa;
            struct ofl_exp_action_set_data_variable *da;
            int i;

            uint16_t operand_types;

            sa = (struct ofp_exp_action_set_data_variable *)ext;
            da = (struct ofl_exp_action_set_data_variable *)malloc(sizeof(struct ofl_exp_action_set_data_variable));
            da->header.header.experimenter_id = ntohl(exp->experimenter);
            da->header.act_type = ntohl(ext->act_type);
            *dst = (struct ofl_action_header *)da;
            
            if (*len < sizeof(struct ofp_exp_action_set_data_variable) + ROUND_UP(sizeof(uint32_t)*(ntohl(sa->field_count)),8) ) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET DATA VAR action has invalid length (%zu)", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            if (sa->table_id >= PIPELINE_TABLES) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *ts = ofl_table_to_string(sa->table_id);
                    OFL_LOG_WARN(LOG_MODULE, "Received SET DATA VAR action has invalid table_id (%s).", ts);
                    free(ts);
                }
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
            }

            operand_types = ntohs(sa->operand_types);

            // operand_types=aabbccdde0000000 where aa=operand_1_type, bb=operand_2_type, cc=operand_3_type, dd=operand_4_type and e=output_type

            // operand_1 can be FLOW_DATA_VAR, GLOBAL_DATA_VAR or HEADER_FIELD
            error = check_operands((operand_types>>14)&3,sa->operand_1,"operand_1",false,true);
            if (error)
                return error;
            // operand_2 can be FLOW_DATA_VAR, GLOBAL_DATA_VAR, HEADER_FIELD or CONSTANT
            error = check_operands((operand_types>>12)&3,sa->operand_2,"operand_2",true,true);
            if (error)
                return error;
            // output can be FLOW_DATA_VAR or GLOBAL_DATA_VAR
            error = check_operands((operand_types>>7)&1,sa->output,"output",false,false);
            if (error)
                return error;        

            if (sa->opcode>OPCODE_POLY_SUM){
                OFL_LOG_WARN(LOG_MODULE, "Received SET DATA VAR action has invalid opcode (%u).", sa->opcode );
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_OPCODE);
            }

            if (sa->opcode==OPCODE_AVG || sa->opcode==OPCODE_VAR || sa->opcode==OPCODE_EWMA || sa->opcode==OPCODE_POLY_SUM){
                // operand_3 can be FLOW_DATA_VAR, GLOBAL_DATA_VAR or HEADER_FIELD
                error = check_operands((operand_types>>10)&3,sa->output,"operand_3",false,true);
                if (error)
                    return error;
            }

            if (sa->opcode==OPCODE_POLY_SUM){
                // operand_4 can be FLOW_DATA_VAR, GLOBAL_DATA_VAR or HEADER_FIELD
                error = check_operands((operand_types>>8)&3,sa->output,"operand_4",false,true);
                if (error)
                    return error;
            }

            if (sa->opcode==OPCODE_EWMA && (sa->operand_2<0 || sa->operand_2>EWMA_PARAM_0875))
                OFL_LOG_WARN(LOG_MODULE, "Received SET DATA VAR (opcode EWMA) action has invalid alpha parameter: 0 <= operand_2 <= 6. Using EWMA_PARAM_0500.");

            da->table_id = sa->table_id;
            da->operand_types = ntohs(sa->operand_types);
            da->opcode = sa->opcode;
            da->output = sa->output;
            da->operand_1 = sa->operand_1;
            da->operand_2 = sa->operand_2;
            da->operand_3 = sa->operand_3;
            da->operand_4 = sa->operand_4;
            da->coeff_1 = sa->coeff_1;
            da->coeff_2 = sa->coeff_2;
            da->coeff_3 = sa->coeff_3;
            da->coeff_4 = sa->coeff_4;
            da->field_count=ntohl(sa->field_count);
            da->bit = sa->bit;

            for (i=0;i<da->field_count;i++)
                da->fields[i]=ntohl(sa->fields[i]);
            
            *len -= sizeof(struct ofp_exp_action_set_data_variable) + ROUND_UP(sizeof(uint32_t)*(ntohl(sa->field_count)),8);
            break;
        }

        case (OFPAT_EXP_WRITE_CONTEXT_TO_FIELD):
        {
            struct ofp_exp_action_write_context_to_field *sa;
            struct ofl_exp_action_write_context_to_field *da;

            sa = (struct ofp_exp_action_write_context_to_field *)ext;
            da = (struct ofl_exp_action_write_context_to_field *)malloc(sizeof(struct ofl_exp_action_write_context_to_field));
            da->header.header.experimenter_id = ntohl(exp->experimenter);
            da->header.act_type = ntohl(ext->act_type);
            *dst = (struct ofl_action_header *)da;

            if (*len < sizeof(struct ofp_exp_action_write_context_to_field)) {
                OFL_LOG_WARN(LOG_MODULE, "Received WRITE CONTEXT TO FIELD action has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            if (sa->src_type > SOURCE_TYPE_STATE) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received WRITE CONTEXT TO FIELD action has invalid src_type (%u).", sa->src_type);
                }
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_SOURCE_TYPE);
            }

            switch (sa->src_type){
                case SOURCE_TYPE_FLOW_DATA_VAR:
                    if (sa->src_id >= OFPSC_MAX_FLOW_DATA_VAR_NUM){
                        OFL_LOG_WARN(LOG_MODULE, "Received WRITE CONTEXT TO FIELD action has invalid flow data variable id (src_id) (%u).", sa->src_id );
                        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_FLOW_DATA_VAR_ID);
                    }
                    break;
                case SOURCE_TYPE_GLOBAL_DATA_VAR:
                    if (sa->src_id >= OFPSC_MAX_GLOBAL_DATA_VAR_NUM){
                        OFL_LOG_WARN(LOG_MODULE, "Received WRITE CONTEXT TO FIELD action has invalid global data variable id (src_id) (%u).", sa->src_id );
                        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_GLOBAL_DATA_VAR_ID);
                    }
                    break;
                case SOURCE_TYPE_STATE:
                    sa->src_id = 0;
                    break;
            }

            da->src_type = sa->src_type;
            da->src_id = sa->src_id;
            da->dst_field = ntohl(sa->dst_field);

            /* OF spec says: <<Set-Field actions for OXM types OFPXMT_OFB_IN_PORT, OXM_OF_IN_PHY_PORT and OFPXMT_OFB_METADATA are not supported,
            because those are not header fields. The Set-Field action overwrite the header field specified by the OXM type, and perform the
            necessary CRC recalculation based on the header field.>>
            TODO: Should we apply the same assumption for all the other BEBA metadata fields?
            For simplicity we commenred the check below to re-use WRITE CONTEXT TO FIELD avoiding a dedicated WRITE CONTEXT TO METADATA */
            if(da->dst_field == OXM_OF_IN_PORT || da->dst_field == OXM_OF_IN_PHY_PORT
                                    // || da->dst_field == OXM_OF_METADATA
                                    || da->dst_field == OXM_OF_IPV6_EXTHDR
                                    || da->dst_field == OXM_EXP_GLOBAL_STATE
                                    || da->dst_field == OXM_EXP_STATE
                                    || da->dst_field == OXM_EXP_CONDITION0
                                    || da->dst_field == OXM_EXP_CONDITION1
                                    || da->dst_field == OXM_EXP_CONDITION2
                                    || da->dst_field == OXM_EXP_CONDITION3
                                    || da->dst_field == OXM_EXP_CONDITION4
                                    || da->dst_field == OXM_EXP_CONDITION5
                                    || da->dst_field == OXM_EXP_CONDITION6
                                    || da->dst_field == OXM_EXP_CONDITION7
                                    || da->dst_field == OXM_EXP_TIMESTAMP
                                    || da->dst_field == OXM_EXP_RANDOM
                                    || da->dst_field == OXM_EXP_PKT_LEN){
                
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_SET_TYPE);
                break;
            }

            *len -= sizeof(struct ofp_exp_action_write_context_to_field);
            break;
        }
        case (OFPAT_EXP_DECAPSULATE_GTP):
        {
            struct ofp_exp_action_decapsulate_gtp *sa;
            struct ofl_exp_action_decapsulate_gtp *da;

            sa = (struct ofp_exp_action_decapsulate_gtp *) ext;
            da = (struct ofl_exp_action_decapsulate_gtp *) malloc(sizeof(struct ofl_exp_action_decapsulate_gtp));
            da->header.header.experimenter_id = ntohl(exp->experimenter);
            da->header.act_type = ntohl(ext->act_type);
            *dst = (struct ofl_action_header *)da;
            // TODO: error handling

            *len -= sizeof(struct ofp_exp_action_decapsulate_gtp);
            break;
        }
        case (OFPAT_EXP_ENCAPSULATE_GTP):
        {
            struct ofp_exp_action_encapsulate_gtp *sa;
            struct ofl_exp_action_encapsulate_gtp *da;

            sa = (struct ofp_exp_action_encapsulate_gtp *) ext;
            da = (struct ofl_exp_action_encapsulate_gtp *) malloc(sizeof(struct ofl_exp_action_encapsulate_gtp));
            da->header.header.experimenter_id = ntohl(exp->experimenter);
            da->header.act_type = ntohl(ext->act_type);
            *dst = (struct ofl_action_header *)da;

            // TODO: error handling
            da->pkttmp_id = ntohl(sa->pkttmp_id);
            
            *len -= sizeof(struct ofp_exp_action_encapsulate_gtp);
            break;
        }
        case (OFPAT_EXP_SOFT_DECAPSULATE_GTP):
        {
            struct ofp_exp_action_soft_decapsulate_gtp *sa;
            struct ofl_exp_action_soft_decapsulate_gtp *da;

            sa = (struct ofp_exp_action_soft_decapsulate_gtp *) ext;
            da = (struct ofl_exp_action_soft_decapsulate_gtp *) malloc(sizeof(struct ofl_exp_action_soft_decapsulate_gtp));
            da->header.header.experimenter_id = ntohl(exp->experimenter);
            da->header.act_type = ntohl(ext->act_type);
            *dst = (struct ofl_action_header *)da;
            // TODO: error handling

            *len -= sizeof(struct ofp_exp_action_soft_decapsulate_gtp);
            break;
        }
        default:
        {
            struct ofl_action_experimenter *da;
            da = (struct ofl_action_experimenter *)malloc(sizeof(struct ofl_action_experimenter));
            da->experimenter_id = ntohl(exp->experimenter);
            (*dst) = (struct ofl_action_header *)da;
            OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown Beba Experimenter action.");
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_ACTION);
        }
    }
    return 0;
}

int
ofl_exp_beba_act_pack(struct ofl_action_header const *src, struct ofp_action_header *dst)
{

    struct ofl_action_experimenter *exp = (struct ofl_action_experimenter *) src;
    struct ofl_exp_beba_act_header *ext = (struct ofl_exp_beba_act_header *) exp;
    int i=0;

    switch (ext->act_type) {
        case (OFPAT_EXP_SET_STATE):
        {
            struct ofl_exp_action_set_state *sa = (struct ofl_exp_action_set_state *) ext;
            struct ofp_exp_action_set_state *da = (struct ofp_exp_action_set_state *) dst;

            da->header.header.experimenter = htonl(exp->experimenter_id);
            da->header.act_type = htonl(ext->act_type);
            memset(da->header.pad, 0x00, 4);
            da->state = htonl(sa->state);
            da->state_mask = htonl(sa->state_mask);
            da->table_id = sa->table_id;
            memset(da->pad, 0x00, 3);
            da->hard_rollback = htonl(sa->hard_rollback);
            da->idle_rollback = htonl(sa->idle_rollback);
            da->hard_timeout = htonl(sa->hard_timeout);
            da->idle_timeout = htonl(sa->idle_timeout);
            da->bit = sa->bit;
            memset(da->pad2, 0x00, 7);
            da->field_count = htonl(sa->field_count);
            
            for (i=0;i<sa->field_count;i++)
                da->fields[i] = htonl(sa->fields[i]);
            
            //ROUND_UP to 8 bytes
            dst->len = htons(sizeof(struct ofp_exp_action_set_state) + ROUND_UP(sizeof(uint32_t)*(sa->field_count),8));

            return sizeof(struct ofp_exp_action_set_state) + ROUND_UP(sizeof(uint32_t)*(sa->field_count),8);
        }
        case (OFPAT_EXP_SET_GLOBAL_STATE):
        {
            struct ofl_exp_action_set_global_state *sa = (struct ofl_exp_action_set_global_state *) ext;
            struct ofp_exp_action_set_global_state *da = (struct ofp_exp_action_set_global_state *) dst;

            da->header.header.experimenter = htonl(exp->experimenter_id);
            da->header.act_type = htonl(ext->act_type);
            memset(da->header.pad, 0x00, 4);
            da->global_state = htonl(sa->global_state);
            da->global_state_mask = htonl(sa->global_state_mask);
            dst->len = htons(sizeof(struct ofp_exp_action_set_global_state));

            return sizeof(struct ofp_exp_action_set_global_state);
        }
        case (OFPAT_EXP_INC_STATE):
        {
            struct ofl_exp_action_inc_state *sa = (struct ofl_exp_action_inc_state *) ext;
            struct ofp_exp_action_inc_state *da = (struct ofp_exp_action_inc_state *) dst;

            da->header.header.experimenter = htonl(exp->experimenter_id);
            da->header.act_type = htonl(ext->act_type);
            memset(da->header.pad, 0x00, 4);
            da->table_id = sa->table_id;
            memset(da->pad, 0x00, 7);
            dst->len = htons(sizeof(struct ofp_exp_action_inc_state));

            return sizeof(struct ofp_exp_action_inc_state);
        }
        case (OFPAT_EXP_SET_DATA_VAR): 
        {
            struct ofl_exp_action_set_data_variable *sa = (struct ofl_exp_action_set_data_variable *) ext;
            struct ofp_exp_action_set_data_variable *da = (struct ofp_exp_action_set_data_variable *) dst;

            da->header.header.experimenter = htonl(exp->experimenter_id);
            da->header.act_type = htonl(ext->act_type);
            memset(da->header.pad, 0x00, 4);

            da->table_id = sa->table_id;
            da->operand_types = htons(sa->operand_types);
            da->opcode = sa->opcode;
            da->output = sa->output;
            memset(da->pad2, 0x00, 3);
            da->operand_1 = sa->operand_1;
            da->operand_2 = sa->operand_2;
            da->operand_3 = sa->operand_3;
            da->operand_4 = sa->operand_4;
            da->coeff_1 = sa->coeff_1;
            da->coeff_2 = sa->coeff_2;
            da->coeff_3 = sa->coeff_3;
            da->coeff_4 = sa->coeff_4;
            da->bit = sa->bit;
            memset(da->pad3, 0x00, 3);
            da->field_count = htonl(sa->field_count);
            
            for (i=0;i<sa->field_count;i++)
                da->fields[i] = htonl(sa->fields[i]);
            
            //ROUND_UP to 8 bytes
            dst->len = htons(sizeof(struct ofp_exp_action_set_data_variable) + ROUND_UP(sizeof(uint32_t)*(sa->field_count),8));

            return sizeof(struct ofp_exp_action_set_data_variable) + ROUND_UP(sizeof(uint32_t)*(sa->field_count),8);
        }
        case (OFPAT_EXP_WRITE_CONTEXT_TO_FIELD): 
        {
            struct ofl_exp_action_write_context_to_field *sa = (struct ofl_exp_action_write_context_to_field *) ext;
            struct ofp_exp_action_write_context_to_field *da = (struct ofp_exp_action_write_context_to_field *) dst;

            da->header.header.experimenter = htonl(exp->experimenter_id);
            da->header.act_type = htonl(ext->act_type);
            memset(da->header.pad, 0x00, 4);

            da->src_type = sa->src_type;
            da->src_id = sa->src_id;
            da->dst_field = htonl(sa->dst_field);
            memset(da->pad2, 0x00, 2);

            dst->len = htons(sizeof(struct ofp_exp_action_write_context_to_field));

            return sizeof(struct ofp_exp_action_write_context_to_field);
        }
        case (OFPAT_EXP_DECAPSULATE_GTP):
        {
            struct ofl_exp_action_decapsulate_gtp *sa = (struct ofl_exp_action_decapsulate_gtp *) ext;
            struct ofp_exp_action_decapsulate_gtp *da = (struct ofp_exp_action_decapsulate_gtp *) dst;

            da->header.header.experimenter = htonl(exp->experimenter_id);
            da->header.act_type = htonl(ext->act_type);

            dst->len = htons(sizeof(struct ofp_exp_action_decapsulate_gtp));

            return sizeof(struct ofp_exp_action_decapsulate_gtp);
        }
        case (OFPAT_EXP_ENCAPSULATE_GTP):
        {
            struct ofl_exp_action_encapsulate_gtp *sa = (struct ofl_exp_action_encapsulate_gtp *) ext;
            struct ofp_exp_action_encapsulate_gtp *da = (struct ofp_exp_action_encapsulate_gtp *) dst;

            da->header.header.experimenter = htonl(exp->experimenter_id);
            da->header.act_type = htonl(ext->act_type);
            memset(da->pad, 0x00, 4);

            da->pkttmp_id = htonl(sa->pkttmp_id);

            dst->len = htons(sizeof(struct ofp_exp_action_encapsulate_gtp));

            return sizeof(struct ofp_exp_action_encapsulate_gtp);
        }
        case (OFPAT_EXP_SOFT_DECAPSULATE_GTP):
        {
            struct ofl_exp_action_soft_decapsulate_gtp *sa = (struct ofl_exp_action_soft_decapsulate_gtp *) ext;
            struct ofp_exp_action_soft_decapsulate_gtp *da = (struct ofp_exp_action_soft_decapsulate_gtp *) dst;

            da->header.header.experimenter = htonl(exp->experimenter_id);
            da->header.act_type = htonl(ext->act_type);

            dst->len = htons(sizeof(struct ofp_exp_action_soft_decapsulate_gtp));

            return sizeof(struct ofp_exp_action_soft_decapsulate_gtp);
        }
        default:
            return 0;
    }
}

size_t
ofl_exp_beba_act_ofp_len(struct ofl_action_header const *act)
{
    struct ofl_action_experimenter *exp = (struct ofl_action_experimenter *) act;
    struct ofl_exp_beba_act_header *ext = (struct ofl_exp_beba_act_header *) exp;

    switch (ext->act_type) {
        case (OFPAT_EXP_SET_STATE):
        {
            struct ofl_exp_action_set_state *sa = (struct ofl_exp_action_set_state *) act;
            //ROUND_UP to 8 bytes
            return sizeof(struct ofp_exp_action_set_state) + ROUND_UP(sizeof(uint32_t)*(sa->field_count),8);
        }
        case (OFPAT_EXP_SET_GLOBAL_STATE):
            return sizeof(struct ofp_exp_action_set_global_state);
        case (OFPAT_EXP_INC_STATE):
            return sizeof(struct ofp_exp_action_inc_state);
        case (OFPAT_EXP_SET_DATA_VAR):{
            struct ofl_exp_action_set_data_variable *sa = (struct ofl_exp_action_set_data_variable *) act;
            //ROUND_UP to 8 bytes
            return sizeof(struct ofp_exp_action_set_data_variable) + ROUND_UP(sizeof(uint32_t)*(sa->field_count),8);
        }
        case (OFPAT_EXP_WRITE_CONTEXT_TO_FIELD):
            return sizeof(struct ofp_exp_action_write_context_to_field);
        case (OFPAT_EXP_DECAPSULATE_GTP):
            return sizeof(struct ofp_exp_action_decapsulate_gtp);
        case (OFPAT_EXP_ENCAPSULATE_GTP):
            return sizeof(struct ofp_exp_action_encapsulate_gtp);
        case (OFPAT_EXP_SOFT_DECAPSULATE_GTP):
            return sizeof(struct ofp_exp_action_decapsulate_gtp);
        default:
            return 0;
    }
}

char *
ofl_exp_beba_act_to_string(struct ofl_action_header const *act)
{
    struct ofl_action_experimenter *exp = (struct ofl_action_experimenter *) act;
    struct ofl_exp_beba_act_header *ext = (struct ofl_exp_beba_act_header *) exp;

    switch (ext->act_type) {
        case (OFPAT_EXP_SET_STATE):
        {
            struct ofl_exp_action_set_state *a = (struct ofl_exp_action_set_state *)ext;
            char *string = malloc(200);
            sprintf(string, "{set_state=[state=\"%"PRIu32"\",state_mask=\"%"PRIu32"\",table_id=\"%u\",idle_to=\"%u\",hard_to=\"%u\",idle_rb=\"%u\",hard_rb=\"%u\",bit=\"%u\"]}", a->state, a->state_mask, a->table_id,a->idle_timeout,a->hard_timeout,a->idle_rollback,a->hard_rollback,a->bit);
            //TODO Davide: print parametric key fields (if any)
            return string;
        }
        case (OFPAT_EXP_SET_GLOBAL_STATE):
        {
            struct ofl_exp_action_set_global_state *a = (struct ofl_exp_action_set_global_state *)ext;
            char *string = malloc(100);
            char string_value[33];
            masked_value_print(string_value,decimal_to_binary(a->global_state),decimal_to_binary(a->global_state_mask));
            sprintf(string, "{set_global_state=[global_state=%s]}", string_value);
            return string;
        }
        case (OFPAT_EXP_INC_STATE):
        {
            struct ofl_exp_action_inc_state *a = (struct ofl_exp_action_inc_state *)ext;
            char *string = malloc(100);
            sprintf(string, "{inc_state=[table_id=\"%u\"]}", a->table_id);
            return string;
        }
        case (OFPAT_EXP_SET_DATA_VAR):
        {
            struct ofl_exp_action_set_data_variable *a = (struct ofl_exp_action_set_data_variable *)ext;
            char *string = malloc(300);

            // operand_types=aabbccdde0000000 where aa=operand_1_type, bb=operand_2_type, cc=operand_3_type, dd=operand_4_type and e=output_type

            //TODO Davide: create function
            sprintf(string, "{set_data_variable=[table_id=\"%u\",opcode=\"%u\",", a->table_id, a->opcode);
            switch ((a->operand_types>>14)&3){
                case OPERAND_TYPE_FLOW_DATA_VAR:
                    sprintf(string + strlen(string), "operand_1=\"flow_data_var_%u\",",a->operand_1);
                    break;
                case OPERAND_TYPE_GLOBAL_DATA_VAR:
                    sprintf(string + strlen(string), "operand_1=\"global_data_var_%u\",",a->operand_1);
                    break;
                case OPERAND_TYPE_HEADER_FIELD:
                    sprintf(string + strlen(string), "operand_1=\"header_field_%u\",",a->operand_1);
                    break;
            }

            switch ((a->operand_types>>12)&3){
                case OPERAND_TYPE_FLOW_DATA_VAR:
                    sprintf(string + strlen(string), "operand_2=\"flow_data_var_%u\",",a->operand_2);
                    break;
                case OPERAND_TYPE_GLOBAL_DATA_VAR:
                    sprintf(string + strlen(string), "operand_2=\"global_data_var_%u\",",a->operand_2);
                    break;
                case OPERAND_TYPE_HEADER_FIELD:
                    sprintf(string + strlen(string), "operand_2=\"header_field_%u\",",a->operand_2);
                    break;
                case OPERAND_TYPE_CONSTANT:
                    sprintf(string + strlen(string), "operand_2=\"%u\",",a->operand_2);
                    break;
            }

            if (a->opcode==OPCODE_AVG || a->opcode==OPCODE_VAR || a->opcode==OPCODE_EWMA || a->opcode==OPCODE_POLY_SUM){
                switch ((a->operand_types>>10)&3){
                    case OPERAND_TYPE_FLOW_DATA_VAR:
                        sprintf(string + strlen(string), "operand_3=\"flow_data_var_%u\",",a->operand_3);
                        break;
                    case OPERAND_TYPE_GLOBAL_DATA_VAR:
                        sprintf(string + strlen(string), "operand_3=\"global_data_var_%u\",",a->operand_3);
                        break;
                    case OPERAND_TYPE_HEADER_FIELD:
                        sprintf(string + strlen(string), "operand_3=\"header_field_%u\",",a->operand_3);
                        break;
                }
            }

            if (a->opcode==OPCODE_POLY_SUM){
                switch ((a->operand_types>>8)&3){
                    case OPERAND_TYPE_FLOW_DATA_VAR:
                        sprintf(string + strlen(string), "operand_4=\"flow_data_var_%u\",",a->operand_4);
                        break;
                    case OPERAND_TYPE_GLOBAL_DATA_VAR:
                        sprintf(string + strlen(string), "operand_4=\"global_data_var_%u\",",a->operand_4);
                        break;
                    case OPERAND_TYPE_HEADER_FIELD:
                        sprintf(string + strlen(string), "operand_4=\"header_field_%u\",",a->operand_4);
                        break;
                }
                sprintf(string + strlen(string), "coeff_1=\"%d\",coeff_2=\"%d\",coeff_3=\"%d\",coeff_4=\"%d\",",a->coeff_1,a->coeff_2,a->coeff_3,a->coeff_4);
            }

            switch ((a->operand_types>>7)&1){
                case OPERAND_TYPE_FLOW_DATA_VAR:
                    sprintf(string + strlen(string), "output=\"flow_data_var_%u\"",a->output);
                    break;
                case OPERAND_TYPE_GLOBAL_DATA_VAR:
                    sprintf(string + strlen(string), "output=\"global_data_var_%u\"",a->output);
                    break;
            }
                
            sprintf(string + strlen(string), ",bit=\"%u\"]}", a->bit);
            //TODO Davide: print parametric key fields (if any)
            return string;
        }
        case (OFPAT_EXP_WRITE_CONTEXT_TO_FIELD):
        {
            struct ofl_exp_action_write_context_to_field *a = (struct ofl_exp_action_write_context_to_field *)ext;
            char *string = malloc(200);

            sprintf(string, "{write_context_to_field=[");
            switch (a->src_type){
                case SOURCE_TYPE_FLOW_DATA_VAR:
                    sprintf(string + strlen(string), "src=\"flow_data_var_%u\",",a->src_id);
                    break;
                case SOURCE_TYPE_GLOBAL_DATA_VAR:
                    sprintf(string + strlen(string), "src=\"global_data_var_%u\",",a->src_id);
                    break;
                case SOURCE_TYPE_STATE:
                    sprintf(string + strlen(string), "src=\"state\",");
                    break;
            }

            sprintf(string + strlen(string), "field=\"");
            sprintf(string + strlen(string), ofl_oxm_type_to_string(a->dst_field));
            sprintf(string + strlen(string), "\"]}");
            return string;
        }
        case (OFPAT_EXP_DECAPSULATE_GTP):
            return "{decapsulate_gtp()}";
        case (OFPAT_EXP_ENCAPSULATE_GTP):
            return "{encapsulate_gtp()}";
        case (OFPAT_EXP_SOFT_DECAPSULATE_GTP):
            return "{soft_decapsulate_gtp()}";
        
    }
    return NULL;
}

int
ofl_exp_beba_act_free(struct ofl_action_header *act) {
    struct ofl_action_experimenter *exp = (struct ofl_action_experimenter *) act;
    struct ofl_exp_beba_act_header *ext = (struct ofl_exp_beba_act_header *) exp;
    switch (ext->act_type) {
        case (OFPAT_EXP_SET_STATE): {
            struct ofl_exp_action_set_state *a = (struct ofl_exp_action_set_state *) ext;
            free(a);
            break;
        }
        case (OFPAT_EXP_SET_GLOBAL_STATE): {
            struct ofl_exp_action_set_global_state *a = (struct ofl_exp_action_set_global_state *) ext;
            free(a);
            break;
        }
        case (OFPAT_EXP_INC_STATE): {
            struct ofl_exp_action_inc_state *a = (struct ofl_exp_action_inc_state *) ext;
            free(a);
            break;
        }
        case (OFPAT_EXP_SET_DATA_VAR): {
            struct ofl_exp_action_set_data_variable *a = (struct ofl_exp_action_set_data_variable *) ext;
            free(a);
            break;
        }
        case (OFPAT_EXP_WRITE_CONTEXT_TO_FIELD):
        {
            struct ofl_exp_action_write_context_to_field *a = (struct ofl_exp_action_write_context_to_field *)ext;
            free(a);
            break;
        }
        case (OFPAT_EXP_DECAPSULATE_GTP):
        {
            struct ofl_exp_action_decapsulate_gtp *a = (struct ofl_exp_action_decapsulate_gtp *)ext;
            free(a);
            break;
        }
        case (OFPAT_EXP_ENCAPSULATE_GTP):
        {
            struct ofl_exp_action_encapsulate_gtp *a = (struct ofl_exp_action_encapsulate_gtp *)ext;
            free(a);
            break;
        }
        case (OFPAT_EXP_SOFT_DECAPSULATE_GTP):
        {
            struct ofl_exp_action_soft_decapsulate_gtp *a = (struct ofl_exp_action_soft_decapsulate_gtp *)ext;
            free(a);
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Beba Experimenter action.");
        }
    }
        return 0;
}

int
ofl_exp_beba_stats_req_pack(struct ofl_msg_multipart_request_experimenter const *ext, uint8_t **buf,
                            size_t *buf_len, struct ofl_exp const *exp) {
    struct ofl_exp_beba_msg_multipart_request *e = (struct ofl_exp_beba_msg_multipart_request *) ext;
    switch (e->type) {
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS): {
            struct ofl_exp_msg_multipart_request_state *msg = (struct ofl_exp_msg_multipart_request_state *) e;
            struct ofp_multipart_request *req;
            struct ofp_exp_state_stats_request *stats;
            struct ofp_experimenter_stats_header *exp_header;
            uint8_t *ptr;
            *buf_len = ROUND_UP(sizeof(struct ofp_multipart_request) + sizeof(struct ofp_exp_state_stats_request) -4 + msg->match->length,8);
            *buf = (uint8_t *) malloc(*buf_len);

            req = (struct ofp_multipart_request *) (*buf);
            stats = (struct ofp_exp_state_stats_request *) req->body;
            exp_header = (struct ofp_experimenter_stats_header *) stats;
            exp_header->experimenter = htonl(BEBA_VENDOR_ID);
            exp_header->exp_type = htonl(OFPMP_EXP_STATE_STATS);
            if (e->type == OFPMP_EXP_STATE_STATS)
                exp_header->exp_type = htonl(OFPMP_EXP_STATE_STATS);
            else if (e->type == OFPMP_EXP_STATE_STATS_AND_DELETE)
                exp_header->exp_type = htonl(OFPMP_EXP_STATE_STATS_AND_DELETE);
            stats->table_id = msg->table_id;
            stats->get_from_state = msg->get_from_state;
            stats->state = htonl(msg->state);
            memset(stats->pad, 0x00, 2);
            ptr = (*buf) + sizeof(struct ofp_multipart_request) + sizeof(struct ofp_exp_state_stats_request);
            ofl_structs_match_pack(msg->match, &(stats->match), ptr, exp);
            return 0;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS): {
            struct ofp_multipart_request *req;
            struct ofp_exp_global_state_stats_request *stats;
            struct ofp_experimenter_stats_header *exp_header;
            *buf_len = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_exp_global_state_stats_request);
            *buf = (uint8_t *) malloc(*buf_len);

            req = (struct ofp_multipart_request *) (*buf);
            stats = (struct ofp_exp_global_state_stats_request *) req->body;
            exp_header = (struct ofp_experimenter_stats_header *) stats;
            exp_header->experimenter = htonl(BEBA_VENDOR_ID);
            exp_header->exp_type = htonl(OFPMP_EXP_GLOBAL_STATE_STATS);

            return 0;

        }
        default:
            return -1;
    }
}


int
ofl_exp_beba_stats_reply_pack(struct ofl_msg_multipart_reply_experimenter const *ext, uint8_t **buf,
                              size_t *buf_len, struct ofl_exp const *exp) {
    struct ofl_exp_beba_msg_multipart_reply *e = (struct ofl_exp_beba_msg_multipart_reply *) ext;
    switch (e->type) {
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS): {
            struct ofl_exp_msg_multipart_reply_state *msg = (struct ofl_exp_msg_multipart_reply_state *) e;
            struct ofp_experimenter_stats_header *ext_header;
            struct ofp_multipart_reply *resp;
            size_t i;
            uint8_t *data;

            *buf_len = sizeof(struct ofp_multipart_reply) + sizeof(struct ofp_experimenter_stats_header) +
                       ofl_structs_state_stats_ofp_total_len(msg->stats, msg->stats_num, exp);
            *buf = (uint8_t *) malloc(*buf_len);
            resp = (struct ofp_multipart_reply *) (*buf);
            data = (uint8_t *) resp->body;
            ext_header = (struct ofp_experimenter_stats_header *) data;
            ext_header->experimenter = htonl(BEBA_VENDOR_ID);
            ext_header->exp_type = htonl(OFPMP_EXP_STATE_STATS);
            if (e->type == OFPMP_EXP_STATE_STATS)
                ext_header->exp_type = htonl(OFPMP_EXP_STATE_STATS);
            else if (e->type == OFPMP_EXP_STATE_STATS_AND_DELETE)
                ext_header->exp_type = htonl(OFPMP_EXP_STATE_STATS_AND_DELETE);

            data += sizeof(struct ofp_experimenter_stats_header);
            for (i = 0; i < msg->stats_num; i++) {
                data += ofl_structs_state_stats_pack(msg->stats[i], data, exp);
            }
            return 0;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS): {
            struct ofl_exp_msg_multipart_reply_global_state *msg = (struct ofl_exp_msg_multipart_reply_global_state *) e;
            struct ofp_multipart_reply *resp;
            struct ofp_exp_global_state_stats *stats;
            struct ofp_experimenter_stats_header *exp_header;

            *buf_len = sizeof(struct ofp_multipart_reply) + sizeof(struct ofp_exp_global_state_stats);
            *buf = (uint8_t *) malloc(*buf_len);

            resp = (struct ofp_multipart_reply *) (*buf);
            stats = (struct ofp_exp_global_state_stats *) resp->body;
            exp_header = (struct ofp_experimenter_stats_header *) stats;

            exp_header->experimenter = htonl(BEBA_VENDOR_ID);
            exp_header->exp_type = htonl(OFPMP_EXP_GLOBAL_STATE_STATS);
            memset(stats->pad, 0x00, 4);
            stats->global_state = htonl(msg->global_state);
            return 0;
        }
        default:
            return -1;
    }
}

ofl_err
ofl_exp_beba_stats_req_unpack(struct ofp_multipart_request const *os, uint8_t const *buf, size_t *len,
                              struct ofl_msg_multipart_request_header **msg, struct ofl_exp const *exp) {
    struct ofp_experimenter_stats_header *ext = (struct ofp_experimenter_stats_header *) os->body;
    switch (ntohl(ext->exp_type)) {
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS): {
            struct ofp_exp_state_stats_request *sm;
            struct ofl_exp_msg_multipart_request_state *dm;
            ofl_err error = 0;
            int match_pos;
            bool check_prereq = 0;

            // ofp_multipart_request length was checked at ofl_msg_unpack_multipart_request

            if (*len < (sizeof(struct ofp_exp_state_stats_request) - sizeof(struct ofp_match))) {
                OFL_LOG_WARN(LOG_MODULE, "Received STATE stats request has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
            }
            *len -= ((sizeof(struct ofp_exp_state_stats_request)) - sizeof(struct ofp_match));

            sm = (struct ofp_exp_state_stats_request *) ext;
            dm = (struct ofl_exp_msg_multipart_request_state *) malloc(
                    sizeof(struct ofl_exp_msg_multipart_request_state));

            if (sm->table_id != OFPTT_ALL && sm->table_id >= PIPELINE_TABLES) {
                OFL_LOG_WARN(LOG_MODULE, "Received MULTIPART REQUEST STATE message has invalid table id (%d).",
                             sm->table_id);
                free(dm);
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
            }
            dm->header.type = ntohl(ext->exp_type);
            dm->header.header.experimenter_id = ntohl(ext->experimenter);
            dm->table_id = sm->table_id;
            dm->get_from_state = sm->get_from_state;
            dm->state = ntohl(sm->state);
            match_pos = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_exp_state_stats_request) - 4;
            error = ofl_structs_match_unpack(&(sm->match), buf + match_pos, len, &(dm->match), check_prereq, exp);
            if (error) {
                free(dm);
                return error;
            }

            *msg = (struct ofl_msg_multipart_request_header *) dm;
            return 0;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS): {
            struct ofl_exp_msg_multipart_request_global_state *dm;
            dm = (struct ofl_exp_msg_multipart_request_global_state *) malloc(
                    sizeof(struct ofl_exp_msg_multipart_request_global_state));
            dm->header.type = ntohl(ext->exp_type);
            dm->header.header.experimenter_id = ntohl(ext->experimenter);
            *len -= sizeof(struct ofp_exp_global_state_stats_request);
            *msg = (struct ofl_msg_multipart_request_header *) dm;
            return 0;
        }
        default:
            return -1;
    }
}

ofl_err
ofl_exp_beba_stats_reply_unpack(struct ofp_multipart_reply const *os, uint8_t const *buf, size_t *len,
                                struct ofl_msg_multipart_reply_header **msg, struct ofl_exp const *exp) {
    struct ofp_experimenter_stats_header *ext = (struct ofp_experimenter_stats_header *) os->body;
    switch (ntohl(ext->exp_type)) {
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS): {
            struct ofp_exp_state_stats *stat;
            struct ofl_exp_msg_multipart_reply_state *dm;
            ofl_err error;
            size_t i, ini_len;
            uint8_t const *ptr;

            // ofp_multipart_reply was already checked and subtracted in unpack_multipart_reply
            stat = (struct ofp_exp_state_stats *) (os->body + sizeof(struct ofp_experimenter_stats_header));
            dm = (struct ofl_exp_msg_multipart_reply_state *) malloc(
                    sizeof(struct ofl_exp_msg_multipart_reply_state));
            dm->header.type = ntohl(ext->exp_type);
            dm->header.header.experimenter_id = ntohl(ext->experimenter);
            *len -= (sizeof(struct ofp_experimenter_stats_header));
            error = ofl_utils_count_ofp_state_stats(stat, *len, &dm->stats_num);
            if (error) {
                free(dm);
                return error;
            }
            dm->stats = (struct ofl_exp_state_stats **) malloc(
                    dm->stats_num * sizeof(struct ofl_exp_state_stats *));

            ini_len = *len;
            ptr = buf + sizeof(struct ofp_multipart_reply) + sizeof(struct ofp_experimenter_stats_header);
            for (i = 0; i < dm->stats_num; i++) {
                error = ofl_structs_state_stats_unpack(stat, ptr, len, &(dm->stats[i]), exp);
                ptr += ini_len - *len;
                ini_len = *len;
                if (error) {
                    free(dm);
                    return error;
                }
                stat = (struct ofp_exp_state_stats *) ((uint8_t *) stat + ntohs(stat->length));
            }

            *msg = (struct ofl_msg_multipart_reply_header *) dm;
            return 0;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS): {
            struct ofp_exp_global_state_stats *sm;
            struct ofl_exp_msg_multipart_reply_global_state *dm;

            if (*len < sizeof(struct ofp_exp_global_state_stats)) {
                OFL_LOG_WARN(LOG_MODULE, "Received GLOBAL STATE stats reply has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
            }
            *len -= sizeof(struct ofp_exp_global_state_stats);

            sm = (struct ofp_exp_global_state_stats *) os->body;
            dm = (struct ofl_exp_msg_multipart_reply_global_state *) malloc(
                    sizeof(struct ofl_exp_msg_multipart_reply_global_state));
            dm->header.type = ntohl(ext->exp_type);
            dm->header.header.experimenter_id = ntohl(ext->experimenter);
            dm->global_state = ntohl(sm->global_state);

            *msg = (struct ofl_msg_multipart_reply_header *) dm;
            return 0;
        }
        default:
            return -1;
    }
}

char *
ofl_exp_beba_stats_request_to_string(struct ofl_msg_multipart_request_experimenter const *ext,
                                     struct ofl_exp const *exp) {
    struct ofl_exp_beba_msg_multipart_request const *e = (struct ofl_exp_beba_msg_multipart_request const *) ext;
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    switch (e->type) {
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS): {
            struct ofl_exp_msg_multipart_request_state const *msg = (struct ofl_exp_msg_multipart_request_state const *) e;
            fprintf(stream, "{exp_type=\"");
            ofl_exp_stats_type_print(stream, e->type);
            fprintf(stream, "\", table=\"");
            ofl_table_print(stream, msg->table_id);
            if (msg->get_from_state)
                fprintf(stream, "\", state=\"%u\"", msg->state);
            fprintf(stream, "\", match=");
            ofl_structs_match_print(stream, msg->match, exp);
            break;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS): {
            fprintf(stream, "{stat_exp_type=\"");
            ofl_exp_stats_type_print(stream, e->type);
            fprintf(stream, "\"");
            break;
        }
    }
    fclose(stream);
    return str;
}

char *
ofl_exp_beba_stats_reply_to_string(struct ofl_msg_multipart_reply_experimenter const *ext,
                                   struct ofl_exp const *exp) {
    struct ofl_exp_beba_msg_multipart_reply *e = (struct ofl_exp_beba_msg_multipart_reply *) ext;
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    switch (e->type) {
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS): {
            struct ofl_exp_msg_multipart_reply_state *msg = (struct ofl_exp_msg_multipart_reply_state *) e;
            size_t i;
            size_t last_table_id = -1;

            fprintf(stream, "{exp_type=\"");
            ofl_exp_stats_type_print(stream, e->type);
            fprintf(stream, "\", stats=[");

            for (i = 0; i < msg->stats_num; i++) {

                if (last_table_id != msg->stats[i]->table_id && ofl_colored_output())
                    fprintf(stream, "\n\n\x1B[33mTABLE = %d\x1B[0m\n\n", msg->stats[i]->table_id);
                last_table_id = msg->stats[i]->table_id;
                ofl_structs_state_stats_print(stream, msg->stats[i], exp);
                if (i < msg->stats_num - 1) {
                    if (ofl_colored_output())
                        fprintf(stream, ",\n\n");
                    else
                        fprintf(stream, ", ");
                };
            }
            if (ofl_colored_output())
                fprintf(stream, "\n\n");
            fprintf(stream, "]");
            break;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS): {
            struct ofl_exp_msg_multipart_reply_global_state *msg = (struct ofl_exp_msg_multipart_reply_global_state *) e;
            char *bin_value = decimal_to_binary(msg->global_state);
            fprintf(stream, "{stat_exp_type=\"");
            ofl_exp_stats_type_print(stream, e->type);
            fprintf(stream, "\", global_state=\"%s\"", bin_value);
            free(bin_value);
            break;
        }
    }
    fclose(stream);
    return str;
}

int
ofl_exp_beba_stats_req_free(struct ofl_msg_multipart_request_header *msg) {
    struct ofl_msg_multipart_request_experimenter *exp = (struct ofl_msg_multipart_request_experimenter *) msg;
    struct ofl_exp_beba_msg_multipart_request *ext = (struct ofl_exp_beba_msg_multipart_request *) exp;
    switch (ext->type) {
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS): {
            struct ofl_exp_msg_multipart_request_state *a = (struct ofl_exp_msg_multipart_request_state *) ext;
            ofl_structs_free_match(a->match,NULL);
            free(a);
            break;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS): {
            struct ofl_exp_msg_multipart_request_global_state *a = (struct ofl_exp_msg_multipart_request_global_state *) ext;
            free(a);
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Beba Experimenter message.");
        }
    }
    return 0;
}

int
ofl_exp_beba_stats_reply_free(struct ofl_msg_multipart_reply_header *msg) {
    struct ofl_msg_multipart_reply_experimenter *exp = (struct ofl_msg_multipart_reply_experimenter *) msg;
    struct ofl_exp_beba_msg_multipart_reply *ext = (struct ofl_exp_beba_msg_multipart_reply *) exp;
    int i;
    switch (ext->type) {
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS): {
            struct ofl_exp_msg_multipart_reply_state *a = (struct ofl_exp_msg_multipart_reply_state *) ext;
            for (i=0; i<a->stats_num; i++) {
                free(a->stats[i]);
            }
            free(a->stats);
            free(a);
            break;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS): {
            struct ofl_exp_msg_multipart_reply_global_state *a = (struct ofl_exp_msg_multipart_reply_global_state *) ext;
            free(a);
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Beba Experimenter message.");
        }
    }
    return 0;
}

int
ofl_exp_beba_field_unpack(struct ofl_match *match, struct oxm_field const *f, void const *experimenter_id,
                          void const *value, void const *mask) {
    switch (f->index) {
        case OFI_OXM_EXP_STATE: {
            ofl_structs_match_exp_put32(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                        ntohl(*((uint32_t *) value)));
            return 0;
        }
        case OFI_OXM_EXP_STATE_W: {
            ofl_structs_match_exp_put32m(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                         ntohl(*((uint32_t *) value)), ntohl(*((uint32_t *) mask)));
            if (check_bad_wildcard32(ntohl(*((uint32_t *) value)), ntohl(*((uint32_t *) mask)))) {
                return ofp_mkerr(OFPET_EXPERIMENTER, OFPEC_BAD_MATCH_WILDCARD);
            }
            return 0;
        }
        case OFI_OXM_EXP_GLOBAL_STATE: {
            ofl_structs_match_exp_put32(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                        ntohl(*((uint32_t *) value)));
            return 0;
        }
        case OFI_OXM_EXP_GLOBAL_STATE_W: {
            ofl_structs_match_exp_put32m(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                         ntohl(*((uint32_t *) value)), ntohl(*((uint32_t *) mask)));
            if (check_bad_wildcard32(ntohl(*((uint32_t *) value)), ntohl(*((uint32_t *) mask)))) {
                return ofp_mkerr(OFPET_EXPERIMENTER, OFPEC_BAD_MATCH_WILDCARD);
            }
            return 0;
        }
        case OFI_OXM_EXP_CONDITION0: {
            ofl_structs_match_exp_put8(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                       *((uint8_t *) value));
            return 0;
        }
        case OFI_OXM_EXP_CONDITION1: {
            ofl_structs_match_exp_put8(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                       *((uint8_t *) value));
            return 0;
        }
        case OFI_OXM_EXP_CONDITION2: {
            ofl_structs_match_exp_put8(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                       *((uint8_t *) value));
            return 0;
        }
        case OFI_OXM_EXP_CONDITION3: {
            ofl_structs_match_exp_put8(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                       *((uint8_t *) value));
            return 0;
        }
        case OFI_OXM_EXP_CONDITION4: {
            ofl_structs_match_exp_put8(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                       *((uint8_t *) value));
            return 0;
        }
        case OFI_OXM_EXP_CONDITION5: {
            ofl_structs_match_exp_put8(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                       *((uint8_t *) value));
            return 0;
        }
        case OFI_OXM_EXP_CONDITION6: {
            ofl_structs_match_exp_put8(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                       *((uint8_t *) value));
            return 0;
        }
        case OFI_OXM_EXP_CONDITION7: {
            ofl_structs_match_exp_put8(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                       *((uint8_t *) value));
            return 0;
        }
        case OFI_OXM_EXP_TIMESTAMP: {
            ofl_structs_match_exp_put32(match, f->header, ntohl(*((uint32_t *) experimenter_id)),
                                        ntohl(*((uint32_t *) value)));
            return 0;
        }
        case OFI_OXM_EXP_RANDOM:{
            ofl_structs_match_exp_put16(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohs(*((uint16_t*) value)));
            return 0;
        }
        case OFI_OXM_EXP_PKT_LEN:{
            ofl_structs_match_exp_put16(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohs(*((uint16_t*) value)));
            return 0;
        }
        default:
            NOT_REACHED();
    }
}

void
ofl_exp_beba_field_pack(struct ofpbuf *buf, struct ofl_match_tlv const *oft) {
    uint8_t length = OXM_LENGTH(oft->header);
    bool has_mask = false;

    length = length - EXP_ID_LEN;      /* field length should exclude experimenter_id */
    if (OXM_HASMASK(oft->header)) {
        length = length / 2;
        has_mask = true;
    }
    switch (length) {
        case (sizeof(uint8_t)): {
            uint32_t experimenter_id;
            uint8_t value;
            memcpy(&experimenter_id, oft->value, sizeof(uint32_t));
            memcpy(&value, oft->value + EXP_ID_LEN, sizeof(uint8_t));
            if (!has_mask)
                oxm_put_exp_8(buf, oft->header, htonl(experimenter_id), value);
            else {
                uint8_t mask;
                memcpy(&mask, oft->value + EXP_ID_LEN + length, sizeof(uint8_t));
                oxm_put_exp_8w(buf, oft->header, htonl(experimenter_id), value, mask);
            }
            break;
        }
        case (sizeof(uint16_t)): {
            uint32_t experimenter_id;
            uint16_t value;
            memcpy(&experimenter_id, oft->value, sizeof(uint32_t));
            memcpy(&value, oft->value + EXP_ID_LEN, sizeof(uint16_t));
            if (!has_mask)
                oxm_put_exp_16(buf, oft->header, htonl(experimenter_id), htons(value));
            else {
                uint16_t mask;
                memcpy(&mask, oft->value + EXP_ID_LEN + length, sizeof(uint16_t));
                oxm_put_exp_16w(buf, oft->header, htonl(experimenter_id), htons(value), htons(mask));
            }
            break;
        }
        case (sizeof(uint32_t)): {
            uint32_t experimenter_id, value;
            memcpy(&experimenter_id, oft->value, sizeof(uint32_t));
            memcpy(&value, oft->value + EXP_ID_LEN, sizeof(uint32_t));
            if (!has_mask)
                oxm_put_exp_32(buf, oft->header, htonl(experimenter_id), htonl(value));
            else {
                uint32_t mask;
                memcpy(&mask, oft->value + EXP_ID_LEN + length, sizeof(uint32_t));
                oxm_put_exp_32w(buf, oft->header, htonl(experimenter_id), htonl(value), htonl(mask));
            }
            break;
        }
        case (sizeof(uint64_t)): {
            uint32_t experimenter_id;
            uint64_t value;
            memcpy(&experimenter_id, oft->value, sizeof(uint32_t));
            memcpy(&value, oft->value + EXP_ID_LEN, sizeof(uint64_t));
            if (!has_mask)
                oxm_put_exp_64(buf, oft->header, htonl(experimenter_id), hton64(value));
            else {
                uint64_t mask;
                memcpy(&mask, oft->value + EXP_ID_LEN + length, sizeof(uint64_t));
                oxm_put_exp_64w(buf, oft->header, htonl(experimenter_id), hton64(value), hton64(mask));
            }
            break;
        }
    }
}

void
ofl_exp_beba_field_match(struct ofl_match_tlv *f, int *packet_header, int *field_len, uint8_t **flow_val,
                         uint8_t **flow_mask) {
    bool has_mask = OXM_HASMASK(f->header);
    (*field_len) = (OXM_LENGTH(f->header) - EXP_ID_LEN);
    *flow_val = f->value + EXP_ID_LEN;
    if (has_mask) {
        /* Clear the has_mask bit and divide the field_len by two in the packet field header */
        *field_len /= 2;
        (*packet_header) &= 0xfffffe00;
        (*packet_header) |= (*field_len) + EXP_ID_LEN;
        *flow_mask = f->value + EXP_ID_LEN + (*field_len);
    }
}

void
ofl_exp_beba_field_compare(struct ofl_match_tlv *packet_f, uint8_t **packet_val) {
    *packet_val = packet_f->value + EXP_ID_LEN;
}

void
ofl_exp_beba_field_match_std(struct ofl_match_tlv *flow_mod_match, struct ofl_match_tlv *flow_entry_match UNUSED,
                             int *field_len, uint8_t **flow_mod_val, uint8_t **flow_entry_val,
                             uint8_t **flow_mod_mask, uint8_t **flow_entry_mask) {
    bool has_mask = OXM_HASMASK(flow_mod_match->header);
    *field_len = OXM_LENGTH(flow_mod_match->header) - EXP_ID_LEN;
    *flow_mod_val = ((*flow_mod_val) + EXP_ID_LEN);
    *flow_entry_val = ((*flow_entry_val) + EXP_ID_LEN);
    if (has_mask) {
        *field_len /= 2;
        *flow_mod_mask = ((*flow_mod_val) + (*field_len));
        *flow_entry_mask = ((*flow_entry_val) + (*field_len));
    }
}

void
ofl_exp_beba_field_overlap_a(struct ofl_match_tlv *f_a, int *field_len, uint8_t **val_a, uint8_t **mask_a,
                             int *header, int *header_m, uint64_t *all_mask) {
    *field_len = OXM_LENGTH(f_a->header) - EXP_ID_LEN;
    *val_a = f_a->value + EXP_ID_LEN;
    if (OXM_HASMASK(f_a->header)) {
        *field_len /= 2;
        *header = ((f_a->header & 0xfffffe00) | ((*field_len) + EXP_ID_LEN));
        *header_m = f_a->header;
        *mask_a = f_a->value + EXP_ID_LEN + (*field_len);
    } else {
        *header = f_a->header;
        *header_m = (f_a->header & 0xfffffe00) | 0x100 | (*field_len << 1);
        /* Set a dummy mask with all bits set to 0 (valid) */
        *mask_a = (uint8_t *) all_mask;
    }
}

void
ofl_exp_beba_field_overlap_b(struct ofl_match_tlv *f_b, int *field_len, uint8_t **val_b, uint8_t **mask_b,
                             uint64_t *all_mask) {
    *val_b = f_b->value + EXP_ID_LEN;
    if (OXM_HASMASK(f_b->header)) {
        *mask_b = f_b->value + EXP_ID_LEN + (*field_len);
    } else {
        /* Set a dummy mask with all bits set to 0 (valid) */
        *mask_b = (uint8_t *) all_mask;
    }
}

/*Experimenter error functions*/
void
ofl_exp_beba_error_pack(struct ofl_msg_exp_error const *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_error_experimenter_msg *exp_err;
    *buf_len = sizeof(struct ofp_error_experimenter_msg) + msg->data_length;
    *buf = (uint8_t *) malloc(*buf_len);

    exp_err = (struct ofp_error_experimenter_msg *) (*buf);
    exp_err->type = htons(msg->type);
    exp_err->exp_type = htons(msg->exp_type);
    exp_err->experimenter = htonl(msg->experimenter);
    memcpy(exp_err->data, msg->data, msg->data_length);
}

void
ofl_exp_beba_error_free(struct ofl_msg_exp_error *msg) {
    free(msg->data);
    free(msg);
}

char *
ofl_exp_beba_error_to_string(struct ofl_msg_exp_error const *msg) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    fprintf(stream, "{type=\"");
    ofl_error_type_print(stream, msg->type);
    fprintf(stream, "\", exp_type=\"");
    ofl_error_beba_exp_type_print(stream, msg->exp_type);
    fprintf(stream, "\", dlen=\"%zu\"}", msg->data_length);
    fprintf(stream, "{id=\"0x%"
    PRIx32
    "\"}", msg->experimenter);
    fclose(stream);
    return str;
}

void
ofl_error_beba_exp_type_print(FILE *stream, uint16_t exp_type) {
    switch (exp_type) {
        case (OFPEC_EXP_STATE_MOD_FAILED): {       fprintf(stream, "OFPEC_EXP_STATE_MOD_FAILED"); return; }
        case (OFPEC_EXP_STATE_MOD_BAD_COMMAND): {     fprintf(stream, "OFPEC_EXP_STATE_MOD_BAD_COMMAND"); return; }
        case (OFPEC_EXP_SET_EXTRACTOR): {        fprintf(stream, "OFPEC_EXP_SET_EXTRACTOR"); return; }
        case (OFPEC_EXP_SET_FLOW_STATE): {       fprintf(stream, "OFPEC_EXP_SET_FLOW_STATE"); return; }
        case (OFPEC_EXP_DEL_FLOW_STATE): {       fprintf(stream, "OFPEC_EXP_DEL_FLOW_STATE"); return; }
        case (OFPEC_BAD_EXP_MESSAGE): {          fprintf(stream, "OFPEC_BAD_EXP_MESSAGE"); return; }
        case (OFPEC_BAD_EXP_ACTION): {           fprintf(stream, "OFPEC_BAD_EXP_ACTION"); return; }
        case (OFPEC_BAD_EXP_LEN): {              fprintf(stream, "OFPEC_BAD_EXP_LEN"); return; }
        case (OFPEC_BAD_TABLE_ID): {             fprintf(stream, "OFPEC_BAD_TABLE_ID"); return; }
        case (OFPEC_BAD_MATCH_WILDCARD): {       fprintf(stream, "OFPEC_BAD_MATCH_WILDCARD"); return; }
        case (OFPET_BAD_EXP_INSTRUCTION): {       fprintf(stream, "OFPET_BAD_EXP_INSTRUCTION"); return; }
        case (OFPEC_EXP_PKTTMP_MOD_FAILED): {       fprintf(stream, "OFPEC_EXP_PKTTMP_MOD_FAILED"); return; }
        case (OFPEC_EXP_PKTTMP_MOD_BAD_COMMAND): {       fprintf(stream, "OFPEC_EXP_PKTTMP_MOD_BAD_COMMAND"); return; }
        case (OFPEC_BAD_EXTRACTOR_ID): {       fprintf(stream, "OFPEC_BAD_EXTRACTOR_ID"); return; }
        case (OFPEC_BAD_CONDITION_ID): {       fprintf(stream, "OFPEC_BAD_CONDITION_ID"); return; }
        case (OFPEC_BAD_CONDITION): {       fprintf(stream, "OFPEC_BAD_CONDITION"); return; }
        case (OFPEC_BAD_OPERAND_TYPE): {       fprintf(stream, "OFPEC_BAD_OPERAND_TYPE"); return; }
        case (OFPEC_BAD_FLOW_DATA_VAR_ID): {       fprintf(stream, "OFPEC_BAD_FLOW_DATA_VAR_ID"); return; }
        case (OFPEC_BAD_GLOBAL_DATA_VAR_ID): {       fprintf(stream, "OFPEC_BAD_GLOBAL_DATA_VAR_ID"); return; }
        case (OFPEC_BAD_HEADER_FIELD_SIZE): {       fprintf(stream, "OFPEC_BAD_HEADER_FIELD_SIZE"); return; }
        case (OFPEC_BAD_OPCODE): {       fprintf(stream, "OFPEC_BAD_OPCODE"); return; }
        case (OFPEC_BAD_HEADER_EXTRACTOR): {       fprintf(stream, "OFPEC_BAD_HEADER_EXTRACTOR"); return; }
        case (OFPEC_BAD_SOURCE_TYPE): {       fprintf(stream, "OFPEC_BAD_SOURCE_TYPE"); return; }
        default: {                               fprintf(stream, "?(%u)", exp_type); return; }
    }
}

struct ofl_exp *
ofl_exp_callbacks() {
    struct ofl_exp *exp = malloc(sizeof(struct ofl_exp));
    struct ofl_exp_act *exp_act = malloc(sizeof(struct ofl_exp_act));

    exp_act->pack      = ofl_exp_beba_act_pack;
    exp_act->unpack    = ofl_exp_beba_act_unpack;
    exp_act->free      = ofl_exp_beba_act_free;
    exp_act->ofp_len   = ofl_exp_beba_act_ofp_len;
    exp_act->to_string = ofl_exp_beba_act_to_string;

    exp->act = exp_act;
    exp->inst = NULL;
    exp->match = NULL;
    exp->stats = NULL;
    exp->msg = NULL;
    exp->field = NULL;
    exp->err = NULL;

    return exp;
}

/* Instruction expertimenter callback implementation */
int
ofl_exp_beba_inst_pack(struct ofl_instruction_header const *src, struct ofp_instruction *dst) {

    struct ofl_instruction_experimenter *exp = (struct ofl_instruction_experimenter *) src;
    struct ofl_exp_beba_instr_header *ext = (struct ofl_exp_beba_instr_header *) exp;

    switch (ext->instr_type) {
        case OFPIT_IN_SWITCH_PKT_GEN: {
            size_t total_len;
            size_t len;
            uint8_t *data;
            size_t i;

            struct ofl_exp_instruction_in_switch_pkt_gen *si = (struct ofl_exp_instruction_in_switch_pkt_gen *) src;
            struct ofp_exp_instruction_in_switch_pkt_gen *di = (struct ofp_exp_instruction_in_switch_pkt_gen *) dst;

            struct ofl_exp *exp_cb = (struct ofl_exp *) ofl_exp_callbacks();
            
            OFL_LOG_DBG(LOG_MODULE, "ofl_exp_beba_inst_pack OFPIT_IN_SWITCH_PKT_GEN");

            total_len = sizeof(struct ofp_exp_instruction_in_switch_pkt_gen) +
                        ofl_actions_ofp_total_len((struct ofl_action_header const **) si->actions, si->actions_num,
                                                  NULL);

            di->header.header.type = htons(src->type); //OFPIT_EXPERIMENTER
            di->header.header.experimenter = htonl(exp->experimenter_id); //BEBA_VENDOR_ID
            di->header.instr_type = htonl(ext->instr_type); //OFPIT_IN_SWITCH_PKT_GEN

            di->header.header.len = htons(total_len);
            memset(di->header.pad, 0x00, 4);

            di->pkttmp_id = htons(si->pkttmp_id);
            memset(di->header.pad, 0x00, 4);
            data = (uint8_t *) dst + sizeof(struct ofp_exp_instruction_in_switch_pkt_gen);

            for (i = 0; i < si->actions_num; i++) {
                len = ofl_actions_pack(si->actions[i], (struct ofp_action_header *) data, data, exp_cb);
                data += len;
            }
            free(exp_cb);
            return total_len;
        }
        default:
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown instruction type.");
            return 0;
    }
}

ofl_err
ofl_exp_beba_inst_unpack(struct ofp_instruction const *src, size_t *len, struct ofl_instruction_header **dst) {

    struct ofl_instruction_header *inst = NULL;
    size_t ilen;
    ofl_err error = 0;
    struct ofp_instruction_experimenter_header *exp;
    struct ofp_beba_instruction_experimenter_header *beba_exp;

    OFL_LOG_DBG(LOG_MODULE, "ofl_exp_beba_inst_unpack");

    if (*len < sizeof(struct ofp_instruction_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER instruction has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp = (struct ofp_instruction_experimenter_header *) src;

    if (*len < ntohs(exp->len)) {
        OFL_LOG_WARN(LOG_MODULE, "Received instruction has invalid length (set to %u, but only %zu received).",
                     ntohs(exp->len), *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    ilen = ntohs(exp->len);

    beba_exp = (struct ofp_beba_instruction_experimenter_header *) exp;
    switch (ntohl(beba_exp->instr_type)) {
        case OFPIT_IN_SWITCH_PKT_GEN: {
            struct ofp_exp_instruction_in_switch_pkt_gen *si;
            struct ofl_exp_instruction_in_switch_pkt_gen *di;
            struct ofp_action_header *act;
            size_t i;

            struct ofl_exp *exp_cb = (struct ofl_exp *) ofl_exp_callbacks();

            di = (struct ofl_exp_instruction_in_switch_pkt_gen *) malloc(
                    sizeof(struct ofl_exp_instruction_in_switch_pkt_gen));
            di->header.header.experimenter_id = ntohl(exp->experimenter); //BEBA_VENDOR_ID
            inst = (struct ofl_instruction_header *) di;

            if (ilen < sizeof(struct ofp_exp_instruction_in_switch_pkt_gen)) {
                OFL_LOG_WARN(LOG_MODULE, "Received IN_SWITCH_PKT_GEN instruction has invalid length (%zu).", *len);
                error = ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            ilen -= sizeof(struct ofp_exp_instruction_in_switch_pkt_gen);

            si = (struct ofp_exp_instruction_in_switch_pkt_gen *) src;

            di->header.instr_type = ntohl(beba_exp->instr_type); //OFPIT_IN_SWITCH_PKT_GEN
            di->pkttmp_id = ntohl(si->pkttmp_id);

            error = ofl_utils_count_ofp_actions((uint8_t *) si->actions, ilen, &di->actions_num);
            if (error) {
                break;
            }
            di->actions = (struct ofl_action_header **) malloc(
                    di->actions_num * sizeof(struct ofl_action_header *));

            act = si->actions;
            for (i = 0; i < di->actions_num; i++) {
                error = ofl_actions_unpack(act, &ilen, &(di->actions[i]), exp_cb);
                if (error) {
                    break;
                }
                act = (struct ofp_action_header *) ((uint8_t *) act + ntohs(act->len));
            }
            free(exp_cb);
            break;
        }
        default: {
            struct ofl_instruction_experimenter *di;
            di = (struct ofl_instruction_experimenter *) malloc(sizeof(struct ofl_instruction_experimenter));
            di->experimenter_id = ntohl(exp->experimenter); //BEBA_VENDOR_ID
            inst = (struct ofl_instruction_header *) di;
            OFL_LOG_WARN(LOG_MODULE, "The received BEBA instruction type (%u) is invalid.",
                         ntohs(beba_exp->instr_type));
            error = ofl_error(OFPET_EXPERIMENTER, OFPET_BAD_EXP_INSTRUCTION);
            break;
        }
    }

    (*dst) = inst;

    if (!error && ilen != 0) {
        *len = *len - ntohs(src->len) + ilen;
        OFL_LOG_WARN(LOG_MODULE, "The received instruction contained extra bytes (%zu).", ilen);
        ofl_exp_beba_inst_free(inst);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= ntohs(src->len);
    return error;
}

int
ofl_exp_beba_inst_free(struct ofl_instruction_header *i) {
    struct ofl_instruction_experimenter *exp = (struct ofl_instruction_experimenter *) i;
    struct ofl_exp_beba_instr_header *ext = (struct ofl_exp_beba_instr_header *) exp;
    struct ofl_exp_instruction_in_switch_pkt_gen *instr;
    switch (ext->instr_type) {
        case (OFPIT_IN_SWITCH_PKT_GEN): {
            OFL_LOG_DBG(LOG_MODULE, "Freeing BEBA instruction IN_SWITCH_PKT_GEN.");
            instr = (struct ofl_exp_instruction_in_switch_pkt_gen *) ext;

            struct ofl_exp *exp_cb = (struct ofl_exp *) ofl_exp_callbacks();

            OFL_UTILS_FREE_ARR_FUN2(instr->actions, instr->actions_num,
                                    ofl_actions_free, exp_cb);
            free(instr);
            free(exp_cb);
            OFL_LOG_DBG(LOG_MODULE, "Done.");
            return 0;
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Unknown BEBA instruction type. Perhaps not freed correctly");
        }
    }
    free(i);
    return 1;
}

size_t
ofl_exp_beba_inst_ofp_len(struct ofl_instruction_header const *i) {
    struct ofl_instruction_experimenter *exp = (struct ofl_instruction_experimenter *) i;

    struct ofl_exp_beba_instr_header *ext = (struct ofl_exp_beba_instr_header *) exp;
    switch (ext->instr_type) {
        case OFPIT_IN_SWITCH_PKT_GEN: {
            struct ofl_exp_instruction_in_switch_pkt_gen *i = (struct ofl_exp_instruction_in_switch_pkt_gen *) ext;
            OFL_LOG_DBG(LOG_MODULE, "ofl_exp_beba_inst_ofp_len");

            struct ofl_exp *exp_cb = (struct ofl_exp *) ofl_exp_callbacks();
            
            size_t s = sizeof(struct ofp_exp_instruction_in_switch_pkt_gen)
                   +
                   ofl_actions_ofp_total_len((struct ofl_action_header const **) i->actions, i->actions_num, exp_cb);
            free(exp_cb);
            return s;
        }
        default:
            OFL_LOG_WARN(LOG_MODULE, "Trying to len unknown BEBA instruction type.");
            return 0;
    }
}

char *
ofl_exp_beba_inst_to_string(struct ofl_instruction_header const *i) {
    struct ofl_instruction_experimenter *exp = (struct ofl_instruction_experimenter *) i;

    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    struct ofl_exp_beba_instr_header *ext = (struct ofl_exp_beba_instr_header *) exp;
    switch (ext->instr_type) {
        case (OFPIT_IN_SWITCH_PKT_GEN): {
            OFL_LOG_DBG(LOG_MODULE, "Trying to print BEBA Experimenter instruction. Not implemented yet!");
            fprintf(stream, "OFPIT{type=\"%u\"}", ext->instr_type);
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown BEBA Experimenter instruction.");
            fprintf(stream, "OFPIT{type=\"%u\"}", ext->instr_type);
        }
    }

    fclose(stream);
    return str;

}

/*experimenter table functions*/

struct state_table *state_table_create(void) {
    int i;
    struct state_table *table = malloc(sizeof(struct state_table));
    memset(table, 0, sizeof(*table));

    table->state_entries = (struct hmap) HMAP_INITIALIZER(&table->state_entries);

    table->default_state_entry.state = STATE_DEFAULT;
    for (i = 0; i < OFPSC_MAX_FLOW_DATA_VAR_NUM; i++)
        table->default_state_entry.flow_data_var[i] = 0;
    table->default_state_entry.stats = xmalloc(sizeof(struct ofl_exp_state_stats));
    memset(table->default_state_entry.stats, 0, sizeof(struct ofl_exp_state_stats));
    // table_id,field_count and fields will be set during lookup-scope configuration
    table->default_state_entry.stats->entry.state = STATE_DEFAULT;

    table->null_state_entry.state = STATE_NULL;
    //TODO Davide should we zero-set all the other fields (stats, etc..)?

    table->last_lookup_state_entry = NULL;
    table->last_update_state_entry = NULL;
    table->update_scope_is_eq_lookup_scope = false;
    table->bit_update_scope_is_eq_lookup_scope = false;

    table->stateful = 0;

    return table;
}

bool state_table_is_enabled(struct state_table *table) {
    return table->stateful
           && table->lookup_key_extractor.field_count != 0
           && table->update_key_extractor.field_count != 0;
}

ofl_err state_table_configure_stateful(struct state_table *table, uint8_t stateful) {
    if (stateful != 0)
        table->stateful = 1;
    else
        table->stateful = 0;
    //TODO Davide: should we "destroy" conditions/extractor/etc?

    return 0;
}

void state_table_destroy(struct state_table *table) {
    struct state_entry *entry, *next;

    HMAP_FOR_EACH_SAFE(entry, next, struct state_entry, hmap_node, &table->state_entries){
        hmap_remove(&table->state_entries, &entry->hmap_node);
        free(entry->stats);
        free(entry);
    }
    free(table->default_state_entry.stats);
    hmap_destroy(&table->state_entries);
    free(table);
}

void swap_struct_biflow(struct struct_biflow *a, struct struct_biflow *b){
    struct struct_biflow c;
    c = *a;
    *a = *b;
    *b = c;
}

int a_min_b(struct struct_biflow *a, struct struct_biflow *b){
    int cnt = 0;

    for (cnt = 0; cnt < a->len; cnt++) {
        if ((a->value)[cnt] != (b->value)[cnt]) {
            if ((a->value)[cnt] < (b->value)[cnt]) {
                return 1;
            } else {
                return 0;
            }
        }
    }
    return 0;
}

void selection_sort(struct struct_biflow *a, int field_count){
    int i = 0, min, j, z;
    int n = OFPSC_MAX_KEY_LEN;

    for(i=0; i < field_count; i++){
        min = i;
        for(j=i+1; j<n; j++){
            if(a[j].type < a[min].type && a[j].type != 0){
                min = j;
            }
        }
        swap_struct_biflow(&a[min],&a[i]);
    }

    i = 0;
    while (i < field_count){
        if(a[i].type == 0)
            return;

        switch (a[i].type) {
            case OXM_OF_ETH_DST:
                if (a[i+1].type == OXM_OF_ETH_SRC) {
                    if ( a_min_b(&a[i],&a[i+1]) ) {
                        swap_struct_biflow(&a[i],&a[i+1]);
                    }
                    i++;
                }
                break;
            case OXM_OF_IPV4_SRC:
                if (a[i+1].type == OXM_OF_IPV4_DST) {
                    if ( a_min_b(&a[i],&a[i+1]) ) {
                        swap_struct_biflow(&a[i],&a[i+1]);
                    }
                    i++;
                }
                break;
            case OXM_OF_TCP_SRC:
                if (a[i+1].type == OXM_OF_TCP_DST) {
                    if ( a_min_b(&a[i],&a[i+1]) ) {
                        swap_struct_biflow(&a[i],&a[i+1]);
                    }
                    i++;
                }
                break;
            case OXM_OF_UDP_SRC:
                if (a[i+1].type == OXM_OF_UDP_DST) {
                    if ( a_min_b(&a[i],&a[i+1]) ) {
                        swap_struct_biflow(&a[i],&a[i+1]);
                    }
                    i++;
                }
                break;
            case OXM_OF_IPV6_SRC:
                if (a[i+1].type == OXM_OF_IPV6_DST) {
                    if ( a_min_b(&a[i],&a[i+1]) ) {
                        swap_struct_biflow(&a[i],&a[i+1]);
                    }
                    i++;
                }
                break;
        }
        i++;
    }
}

/* having the key extractor field goes to look for these key inside the packet and map to corresponding value and copy the value into buf. */
int __extract_key(uint8_t *buf, struct key_extractor *extractor, struct packet *pkt) {
    int i;
    uint32_t extracted_key_len = 0;
    struct ofl_match_tlv *f;
    struct struct_biflow xbiflow[OFPSC_MAX_KEY_LEN] = {0};
    OFL_LOG_DBG(LOG_MODULE, "biflow value = %d", extractor->biflow);

    // if biflow
    if(extractor->biflow){
        for (i = 0; i < extractor->field_count; i++) {
            uint32_t type = (int) extractor->fields[i];
            HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv,
                hmap_node, hash_int(type, 0), &pkt->handle_std.match.match_fields){
                    if (type == f->header) {
                        if (OXM_VENDOR(f->header)==0xFFFF){
                            xbiflow[i].type = f->header;
                            xbiflow[i].value = f->value+EXP_ID_LEN;
                            xbiflow[i].len = (OXM_LENGTH(f->header)-EXP_ID_LEN);
                        } else {
                            xbiflow[i].type = f->header;
                            xbiflow[i].value = f->value;
                            xbiflow[i].len = (OXM_LENGTH(f->header));
                        }
                        break;
                    }
            }
        }

        selection_sort(&xbiflow, extractor->field_count);
        extracted_key_len = 0;

        for (i=0; i<extractor->field_count; i++) {
            memcpy(&buf[extracted_key_len], xbiflow[i].value, xbiflow[i].len);
            extracted_key_len = extracted_key_len + xbiflow[i].len;
        }

    } else {
        for (i = 0; i < extractor->field_count; i++) {
            uint32_t type = (int) extractor->fields[i];
            HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv,
                hmap_node, hash_int(type, 0), &pkt->handle_std.match.match_fields){
                    if (type == f->header) {
                        if (OXM_VENDOR(f->header)==0xFFFF){
                            memcpy(&buf[extracted_key_len], f->value+EXP_ID_LEN, OXM_LENGTH(f->header)-EXP_ID_LEN);
                        } else {
                            memcpy(&buf[extracted_key_len], f->value, OXM_LENGTH(f->header));
                        }
                        extracted_key_len = extracted_key_len + OXM_LENGTH(f->header);//keeps only 8 last bits of oxm_header that contains oxm_length(in which length of oxm_payload)
                        break;
                    }
            }
        }
    }
    /* check if the full key has been extracted: if key is extracted partially or not at all, we cannot access the state table */
    return extracted_key_len == extractor->key_len;
}

bool
state_entry_apply_idle_timeout(struct state_entry *entry, uint64_t now_us) {
    if (entry->stats->idle_timeout != 0) {
        if (now_us > entry->last_used + entry->stats->idle_timeout) {
            entry->state = entry->stats->idle_rollback;
            entry->created = now_us;
            entry->stats->idle_timeout = 0;
            entry->stats->hard_timeout = 0;
            entry->stats->idle_rollback = 0;
            entry->stats->hard_rollback = 0;
            return true;
        }
    }
    return false;
}

bool
state_entry_apply_hard_timeout(struct state_entry *entry, uint64_t now_us) {
    if (entry->stats->hard_timeout != 0) {
        if (now_us > entry->remove_at) {
            entry->state = entry->stats->hard_rollback;
            entry->created = now_us;
            entry->stats->idle_timeout = 0;
            entry->stats->hard_timeout = 0;
            entry->stats->idle_rollback = 0;
            entry->stats->hard_rollback = 0;
            return true;
        }
    }
    return false;
}

bool
can_be_flushed(struct state_entry *entry) {
    int i;

    if (entry->state != STATE_DEFAULT || entry->stats->hard_timeout > 0 || entry->stats->idle_timeout > 0) {
        return false;
    }

    // We assume a state entry in STATE_DEFAULT and without timeouts set a flushable flow regardless of flow_data_var values
    /*for(i=0;i<OFPSC_MAX_FLOW_DATA_VAR_NUM;i++) {
        if (entry->flow_data_var[i] != 0) {
            return false;
        }
    }*/
    
    return true;
}

void
state_table_flush(struct state_table *table, uint64_t now_us) {
    struct state_entry *entry, *next;

    HMAP_FOR_EACH_SAFE(entry, next, struct state_entry, hmap_node, &table->state_entries){
        state_entry_apply_hard_timeout(entry, now_us);
        state_entry_apply_idle_timeout(entry, now_us);
        if (can_be_flushed(entry)) {
            hmap_remove(&table->state_entries, &entry->hmap_node);
            free(entry->stats);
            free(entry);
        }
    }
}

bool retrieve_operand(uint32_t *operand_value, uint8_t operand_type, uint8_t operand_id, char *operand_name,
                      struct state_table *table, struct packet *pkt, struct key_extractor *extractor, bool with_lookup_scope) {
    // Operands IDs validity has been already checked at unpack time
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};
    struct state_entry *state_entry;
    uint8_t field_len;
    uint64_t operand_value64;

    switch (operand_type) {
        case OPERAND_TYPE_FLOW_DATA_VAR: {
            if (with_lookup_scope && table->last_lookup_state_entry != NULL) {
                OFL_LOG_DBG(LOG_MODULE, "Retrieving %s from lookup cache",operand_name);
                state_entry = table->last_lookup_state_entry;
            } else if (!with_lookup_scope && table->last_update_state_entry != NULL) {
                OFL_LOG_DBG(LOG_MODULE, "Retrieving %s from update cache",operand_name);
                state_entry = table->last_update_state_entry;
            }
            else {
                //TODO Davide: ok but if cached entry is NULL it means either the lookup returns DEF or state cannot be extracted
                // If we could distinguish between the two cases we could save another lookup in the first case.
                state_entry = state_table_lookup_from_scope(table, pkt, extractor, with_lookup_scope);
            }

            if (state_entry->state == STATE_NULL) {
                return false;
            } else {
                //in case state_entry==DEFAULT ENTRY, flow_data_var are all set to 0
                *operand_value = (uint32_t) state_entry->flow_data_var[operand_id];
            }
            break;
        }
        case OPERAND_TYPE_GLOBAL_DATA_VAR: {
            OFL_LOG_DBG(LOG_MODULE, "Retrieving %s",operand_name);
            *operand_value = (uint32_t) table->global_data_var[operand_id];
            break;
        }
        case OPERAND_TYPE_HEADER_FIELD: {
            if (table->header_field_extractor[operand_id].field_count != 1) {
                OFL_LOG_DBG(LOG_MODULE,"Retrieving %s: header field exractor not configured (%u).",
                            operand_name, operand_id);
                return false;
            }

            if (!__extract_key(key, &table->header_field_extractor[operand_id], pkt)) {
                OFL_LOG_DBG(LOG_MODULE, "Retrieving %s: field not found in the packet's header -> NULL", operand_name);
                return false;
            }

            field_len = OXM_LENGTH(table->header_field_extractor[operand_id].fields[0]);
            if (OXM_VENDOR(table->header_field_extractor[operand_id].fields[0]) == 0xffff) {
                field_len -= EXP_ID_LEN;
            }
            switch (field_len) {
                case 8: {
                    memcpy(&operand_value64, key, 8);
                    *operand_value = (uint32_t)operand_value64 & 0x0000ffff;
                    break;
                }
                case 6: {
                    memcpy(&operand_value64, key, 6);
                    *operand_value = (uint32_t)operand_value64 & 0x0000ffff;
                    break;
                }
                case 4: {
                    memcpy(operand_value, key, 4);
                    break;
                }
                case 2: {
                    memcpy(operand_value, key, 2);
                    break;
                }
                case 1: {
                    memcpy(operand_value, key, 1);
                    break;
                }
            }
            OFL_LOG_DBG(LOG_MODULE, "operand_value = %d\n", *operand_value);
            break;
        }
        case OPERAND_TYPE_CONSTANT: {
            *operand_value = (uint32_t) operand_id;
            break;
        }
    }
    OFL_LOG_DBG(LOG_MODULE, "%s_value=%"PRIu32"", operand_name, *operand_value);
    return true;
}

int state_table_evaluate_condition(struct state_table *state_table,struct packet *pkt,struct condition_table_entry* condition_table_entry) {
    if (condition_table_entry == NULL) {
        return CONDITION_NULL;
    }

    //Comparison is made by converting fields value to integers. Header field extractors always refer to field of length <=32 bit
    uint32_t operand_1_value = 0;
    uint32_t operand_2_value = 0;
    
    if (!retrieve_operand(&operand_1_value, condition_table_entry->operand_1_type, condition_table_entry->operand_1, "condition_operand_1", state_table, pkt, &state_table->lookup_key_extractor, true))
        return CONDITION_NULL;

    if (!retrieve_operand(&operand_2_value, condition_table_entry->operand_2_type, condition_table_entry->operand_2, "condition_operand_2", state_table, pkt, &state_table->lookup_key_extractor, true))
        return CONDITION_NULL;

    switch(condition_table_entry->condition){
        case CONDITION_GT:{
            OFL_LOG_DBG(LOG_MODULE, "condition=CONDITION_GT");
            return operand_1_value>operand_2_value;}
        case CONDITION_LT:{
            OFL_LOG_DBG(LOG_MODULE, "condition=CONDITION_LT");
            return operand_1_value<operand_2_value;}
        case CONDITION_GTE:{
            OFL_LOG_DBG(LOG_MODULE, "condition=CONDITION_GTE");
            return operand_1_value>=operand_2_value;}
        case CONDITION_LTE:{
            OFL_LOG_DBG(LOG_MODULE, "condition=CONDITION_LTE");
            return operand_1_value<=operand_2_value;}
        case CONDITION_EQ:{
            OFL_LOG_DBG(LOG_MODULE, "condition=CONDITION_EQ");
            return operand_1_value==operand_2_value;}
        case CONDITION_NEQ:{
            OFL_LOG_DBG(LOG_MODULE, "condition=CONDITION_NEQ");
            return operand_1_value!=operand_2_value;}
        default:{
            return CONDITION_NULL;}
        }

    return CONDITION_NULL;
}

/*having the read_key, look for the state value inside the state_table */
struct state_entry * state_table_lookup_from_scope(struct state_table* table, struct packet *pkt, struct key_extractor* key_extract, bool with_lookup_scope)
{
    struct state_entry * e = NULL;
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};
    uint64_t now_us;

    if(!__extract_key(key, key_extract, pkt))
    {
        OFL_LOG_DBG(LOG_MODULE, "lookup key fields not found in the packet's header -> STATE_NULL");
        return &table->null_state_entry;
    }

    HMAP_FOR_EACH_WITH_HASH(e, struct state_entry,
        hmap_node, hash_bytes(key, OFPSC_MAX_KEY_LEN, 0), &table->state_entries){
            if (!memcmp(key, e->key, OFPSC_MAX_KEY_LEN)){
                //TODO Davide: generalize for OFPSC_MAX_FLOW_DATA_VAR_NUM
                OFL_LOG_DBG(LOG_MODULE, "State Table lookup: state entry FOUND %u | %u %u %u %u",e->state,e->flow_data_var[0],e->flow_data_var[1],e->flow_data_var[2],e->flow_data_var[3]);

                now_us = 1000000 * pkt->ts.tv_sec + pkt->ts.tv_usec;

                state_entry_apply_hard_timeout(e, now_us);
                state_entry_apply_idle_timeout(e, now_us);

                e->last_used = now_us;

                if (with_lookup_scope) {
                    table->last_lookup_state_entry = e;
                    if (table->update_scope_is_eq_lookup_scope) {
                        table->last_update_state_entry = e;
                    }
                } else { 
                    table->last_update_state_entry = e;
                }

                return e;
            }
    }

    OFL_LOG_DBG(LOG_MODULE, "State Table lookup: state entry NOT FOUND, returning DEFAULT");
    return &table->default_state_entry;
}

/*having the read_key, look for the state vaule inside the state_table */
struct state_entry * state_table_lookup(struct state_table* table, struct packet *pkt)
{
    return state_table_lookup_from_scope(table, pkt, &table->lookup_key_extractor, true);
}

void state_table_write_state_header(struct state_entry *entry, struct ofl_match_tlv *f) {
    uint32_t *state = (uint32_t *) (f->value + EXP_ID_LEN);
    *state = entry->state;
}

void state_table_write_condition_header(uint8_t result, struct ofl_match_tlv *f) {
    uint8_t *condition_result = (uint8_t *) (f->value + EXP_ID_LEN);
    *condition_result = result;
}

ofl_err state_table_del_state(struct state_table *table, uint8_t *key, uint32_t len) {
    struct state_entry *e;
    uint8_t found = 0;
    struct key_extractor *extractor = &table->update_key_extractor;

    if (extractor->key_len != len) {
        OFL_LOG_WARN(LOG_MODULE, "key extractor length != received key length");
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    HMAP_FOR_EACH_WITH_HASH(e, struct state_entry,
        hmap_node, hash_bytes(key, OFPSC_MAX_KEY_LEN, 0), &table->state_entries){
            if (!memcmp(key, e->key, OFPSC_MAX_KEY_LEN)){
                hmap_remove_and_shrink(&table->state_entries, &e->hmap_node);
                free(e->stats);
                free(e);
                found = 1;
                break;
            }
    }

    if (!found){
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_DEL_FLOW_STATE);
    }

    return 0;
}

bool extractors_are_equal(struct key_extractor *ke1, struct key_extractor *ke2)
{
    int i;

    if (ke1->key_len != ke2->key_len){
        return false;
    }

    for (i = 0; i < ke1->field_count; i++) {
        if (ke1->fields[i] != ke2->fields[i]) {
            return false;
        }
    }

    return true;
}

ofl_err state_table_set_extractor(struct state_table *table, struct key_extractor *ke, int update)
{
    struct key_extractor *dest;
    uint32_t key_len = 0;
	
    //TODO check if the biflow fields are invertible
	
    int i;
    for (i = 0; i < ke->field_count; i++) {
        key_len += OXM_LENGTH((int) ke->fields[i]);
    }

    if (key_len == 0) {
        OFL_LOG_WARN(LOG_MODULE, "Can't set extractor for a 0 length key\n");
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    if (update) {
        // Setting the update scope.

        // Ensure conformity with the length of a previously configured scope
        if (table->lookup_key_extractor.key_len != 0
            && table->lookup_key_extractor.key_len != key_len) {
            OFL_LOG_WARN(LOG_MODULE, "Update-scope should provide same length keys of lookup-scope: %d vs %d\n",
                         key_len, table->lookup_key_extractor.key_len);
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        if (ke->bit == 0 && table->bit_update_key_extractor.key_len != 0
            && table->bit_update_key_extractor.key_len != key_len) {
            OFL_LOG_WARN(LOG_MODULE, "Update-scope should provide same length keys of bit-update-scope: %d vs %d\n",
                         key_len, table->bit_update_key_extractor.key_len);
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        if (ke->bit == 1 && table->update_key_extractor.key_len != 0
            && table->update_key_extractor.key_len != key_len) {
            OFL_LOG_WARN(LOG_MODULE, "Bit-update-scope should provide same length keys of update-scope: %d vs %d\n",
                         key_len, table->update_key_extractor.key_len);
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        // Select the right write key
        if (ke->bit == 0) {
            // Update the normal key extractor
            dest = &table->update_key_extractor;
            OFL_LOG_DBG(LOG_MODULE, "Update-scope set");
        } else {
            // Update the "bit" key extractor
            dest = &table->bit_update_key_extractor;
            OFL_LOG_DBG(LOG_MODULE, "Bit Update-scope set");
        }
    } else {
        // Setting the lookup scope.

        // Ensure conformity with the length of a previously configured scope
        if (table->update_key_extractor.key_len != 0
            && table->update_key_extractor.key_len != key_len) {
            OFL_LOG_WARN(LOG_MODULE, "Lookup-scope should provide same length keys of update-scope: %d vs %d\n",
                         key_len, table->update_key_extractor.key_len);
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        if (table->bit_update_key_extractor.key_len != 0
            && table->bit_update_key_extractor.key_len != key_len) {
            OFL_LOG_WARN(LOG_MODULE, "Lookup-scope should provide same length keys of bit-update-scope: %d vs %d\n",
                         key_len, table->bit_update_key_extractor.key_len);
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        dest = &table->lookup_key_extractor;
        OFL_LOG_DBG(LOG_MODULE, "Lookup-scope set");

        table->default_state_entry.stats->table_id = ke->table_id;
        table->default_state_entry.stats->field_count = ke->field_count;
        memcpy(table->default_state_entry.stats->fields, ke->fields, sizeof(uint32_t) * ke->field_count);
    }
    dest->table_id = ke->table_id;
    dest->biflow = ke->biflow;
    dest->field_count = ke->field_count;
    dest->key_len = key_len;
    memcpy(dest->fields, ke->fields, sizeof(uint32_t) * ke->field_count);

    if (extractors_are_equal(&table->lookup_key_extractor,&table->update_key_extractor)){
        table->update_scope_is_eq_lookup_scope = true;
    }

    if (extractors_are_equal(&table->lookup_key_extractor,&table->bit_update_key_extractor)){
        table->bit_update_scope_is_eq_lookup_scope = true;
    }

    return 0;
}

ofl_err state_table_set_condition(struct state_table *table, struct ofl_exp_set_condition *p) {
    //TODO Davide: check if !=null and return error?! (i.e. check if this condition has been already configured in the past)
    struct condition_table_entry* cte = (struct condition_table_entry*) malloc(sizeof(struct condition_table_entry)); 
    cte->condition = p->condition;
    cte->operand_1_type = (p->operand_types>>6)&3;
    cte->operand_2_type = (p->operand_types>>4)&3;
    //TODO Davide: check if condition is valid (e.g. if operand_1 is header field 2 => header field 2 must have been configured)
    //NB Checking the validity does NOT mean checking if, for example, header field can be extracted (there is no packet here!)
    cte->operand_1 = p->operand_1;
    cte->operand_2 = p->operand_2;
    table->condition_table[p->condition_id] = cte;
    OFL_LOG_DBG(LOG_MODULE, "Condition %u configured",p->condition_id);

    return 0;
}

/* Set-flow-data-variable action */
void state_table_set_data_variable(struct state_table *table, struct ofl_exp_action_set_data_variable *act, struct packet *pkt) {
    // At unpack time we have checked just operands IDs validity. Now, at action execution time, we need to check if stage is
    // stateful and state table is configured.
    uint32_t result1 = 0;
    uint32_t result2 = 0;
    uint32_t result3 = 0;
    uint32_t output_value = 0;
    uint32_t operand_1_value = 0;
    uint32_t operand_2_value = 0;
    uint32_t operand_3_value = 0;
    uint32_t operand_4_value = 0;
    //coeff_x are signed integers!
    int8_t coeff_1 = 0;
    int8_t coeff_2 = 0;
    int8_t coeff_3 = 0;
    int8_t coeff_4 = 0;
    struct key_extractor *extractor=(act->bit==0) ? &table->update_key_extractor : &table->bit_update_key_extractor;

    // operand_types=aabbccdde0000000 where aa=operand_1_type, bb=operand_2_type, cc=operand_3_type, dd=operand_4_type and e=output_type
    if (!retrieve_operand(&operand_1_value, (act->operand_types>>14)&3, act->operand_1, "operand_1", table, pkt, extractor, false))
        return;

    if (!retrieve_operand(&operand_2_value, (act->operand_types>>12)&3, act->operand_2, "operand_2", table, pkt, extractor, false))
        return;

    // operand_3 is needed only by OPCODE_VAR, OPCODE_EWMA and OPCODE_POLY_SUM
    if (act->opcode==OPCODE_VAR || act->opcode==OPCODE_EWMA || act->opcode==OPCODE_POLY_SUM) {
        if (!retrieve_operand(&operand_3_value, (act->operand_types>>10)&3, act->operand_3, "operand_3", table, pkt, extractor, false))
            return;
    }

    // operand_4 and coeff_x are needed only by OPCODE_POLY_SUM
    if (act->opcode==OPCODE_POLY_SUM){
        if (!retrieve_operand(&operand_4_value, (act->operand_types>>8)&3, act->operand_4, "operand_4", table, pkt, extractor, false))
            return;

        coeff_1 = act->coeff_1;
        coeff_2 = act->coeff_2;
        coeff_3 = act->coeff_3;
        coeff_4 = act->coeff_4;
    }

    // OPCODE_AVG and OPCODE_VAR needs the current value of "output" operand
    if (act->opcode==OPCODE_AVG || act->opcode==OPCODE_VAR){
        if (!retrieve_operand(&output_value, (act->operand_types>>7)&1, act->output, "output", table, pkt, extractor, false))
            return;
    }

    
    // Calculate result(s)
    switch(act->opcode){
        case OPCODE_SUM:{
            OFL_LOG_DBG(LOG_MODULE, "Executing OPCODE_SUM");
            // sum( output , in1 , in2) = (OUT1 , IN1 , IN2) has 2 inputs and 1 output
            // output = in1 + in2

            // TODO Davide: overflows/underflows are handled by the user! => what happens when 'counter' for AVG/VAR overflows is under the user's responsibility!
            result1 = operand_1_value + operand_2_value;
            break;}
        case OPCODE_SUB:{
            OFL_LOG_DBG(LOG_MODULE, "Executing OPCODE_SUB");
            // sub( output , in1 , in2) = (OUT1 , IN1 , IN2) has 2 inputs and 1 output
            // output = in1 - in2

            result1 = operand_1_value - operand_2_value;
            break;}
        case OPCODE_MUL:{
            OFL_LOG_DBG(LOG_MODULE, "Executing OPCODE_MUL");
            // mul( output , in1 , in2) = (OUT1 , IN1 , IN2) has 2 inputs and 1 output
            // output = in1 * in2
            
            result1 = operand_1_value * operand_2_value;
            break;}
        case OPCODE_DIV:{
            OFL_LOG_DBG(LOG_MODULE, "Executing OPCODE_DIV");
            // div( output , in1 , in2) = (OUT1 , IN1 , IN2) has 2 inputs and 1 output
            // output = in1 / in2
            
            if (operand_1_value==0)
                result1 = 0;
            else if (operand_2_value==0)
                result1 = 0xffffffff;
            else
                result1 = operand_1_value / operand_2_value;
            break;}
        case OPCODE_AVG:{
            OFL_LOG_DBG(LOG_MODULE, "Executing OPCODE_AVG");
            // avg( [count] , [value_to_be_averaged] , [avg_value]) = (IO1 , IN1 , IO2) has 3 inputs and 2 outputs
            // output1 = count
            // output2 = avg(in1)*1000

            // [count] = [count] + 1
            // [avg_value] = ( [avg_value]*[count] + [value_to_be_averaged] ) / ( [count] + 1 )

            result1 = output_value + 1;
            // It should be
            // result2 = ( (operand_2_value*output_value) + operand_1_value ) / (output_value + 1);
            // but we'd like 3 decimal places
            result2 = ( (operand_2_value*output_value) + operand_1_value*MULTIPLY_FACTOR ) / (output_value + 1);

            break;}
        case OPCODE_VAR:{
            OFL_LOG_DBG(LOG_MODULE, "Executing OPCODE_VAR");
            // var( [count] , [value_to_be_varianced] , [avg_value] , [var_value]) = (IO1 , IN1 , IO2, IO3) has 4 inputs and 3 outputs
            // output1 = count
            // output2 = avg(in1)*1000
            // output3 = var(in1)

            // [count] = [count] + 1
            // [avg_value] = ( [avg_value]*[count] + [value_to_be_averaged] ) / ( [count] + 1 )
            // [var_value] = ( [var_value]*[count] + ([value_to_be_varianced] - [avg_value])*([value_to_be_varianced] - [NEW_avg_value]) ) / ( [count] + 1 )

            /*
            When [count]=0, [var_value] would be set to [value_to_be_varianced]^2 because the HW would calculate [avg_value] in parallel
            with [var_value], so [avg_value] used to compute [var_value] would be still 0!
            Thus, when the first sample is added, [var_value] must be 0!
            */

            result1 = output_value + 1;
            // It should be
            // result2 = ( (operand_2_value*output_value) + operand_1_value ) / (output_value + 1);
            // but we'd like 3 decimal places
            result2 = ( (operand_2_value*output_value) + operand_1_value*MULTIPLY_FACTOR ) / (output_value + 1);
            if (output_value==0)
                result3 = 0;
            else {
                // As result2 is avg_value*1000, operand_2 and resultt2 needto be divided by 1000
                result3 = (( (operand_3_value*output_value) + (operand_1_value-operand_2_value/MULTIPLY_FACTOR)*(operand_1_value-result2/MULTIPLY_FACTOR) ) / (output_value + 1));
            }

            break;}
        case OPCODE_EWMA:{
            OFL_LOG_DBG(LOG_MODULE, "Executing OPCODE_EWMA");
            // ewma( [last_ewma] , [EWMA_PARAM_****],  [current_sample] )
            // output = (1 - alpha)*current_sample + alpha(last_ewma)

            switch (operand_2_value) {
                case EWMA_PARAM_0125:{
                    result1 = (uint32_t) (operand_1_value >> 3)     + (operand_3_value >> 3)*7;
                    break;
                }    
                case EWMA_PARAM_0250:{
                    result1 = (uint32_t) (operand_1_value >> 2)     + (operand_3_value >> 2)*3;
                    break;
                }    
                case EWMA_PARAM_0375:{
                    result1 = (uint32_t) (operand_1_value >> 3)*3   + (operand_3_value >> 3)*5;
                    break;
                }    
                case EWMA_PARAM_0500:{
                    result1 = (uint32_t) (operand_1_value >> 1)     + (operand_3_value >> 1);
                    break;
                }    
                case EWMA_PARAM_0625:{
                    result1 = (uint32_t) (operand_1_value >> 3)*5   + (operand_3_value >> 3)*3;
                    break;
                }    
                case EWMA_PARAM_0750:{
                    result1 = (uint32_t) (operand_1_value >> 2)*3   + (operand_3_value >> 2);
                    break;
                }    
                case EWMA_PARAM_0875:{
                    result1 = (uint32_t) (operand_1_value >> 3)*7   + (operand_3_value >> 3);
                    break;
                }    
                default:{
                    // Default returns a 50/50 average
                    result1 = (uint32_t) (operand_1_value >> 1)     + (operand_3_value >> 1);
                    break;
                }    
            }

            break;}
        case OPCODE_POLY_SUM:{
            OFL_LOG_DBG(LOG_MODULE, "Executing OPCODE_POLY_SUM");
            // polysum( [count] , [value_to_be_varianced] , [avg_value] , [var_value]) = (OUT1 , IN1 , IN2, IN3, COEFF1, COEFF2, COEFF3, COEFF4) has 8 inputs and 1 output
            //output = operand_1_value*coeff_1 + operand_2_value*coeff_2 + operand_3_value*coeff_3 + operand_4_value*coeff_4;

            result1 = 0;
            if (coeff_1<0)
                result1 -= operand_1_value*abs(coeff_1);
            else
                result1 += operand_1_value*coeff_1;

            if (coeff_2<0)
                result1 -= operand_2_value*abs(coeff_2);
            else
                result1 += operand_2_value*coeff_2;

            if (coeff_3<0)
                result1 -= operand_3_value*abs(coeff_3);
            else
                result1 += operand_3_value*coeff_3;

            if (coeff_4<0)
                result1 -= operand_4_value*abs(coeff_4);
            else
                result1 += operand_4_value*coeff_4;

            break;
        }
        default:{
            OFL_LOG_DBG(LOG_MODULE, "SET DATA VAR action has invalid opcode (%u).", act->opcode );
            return;}
    }

    // Write results to the corresponding output(s)
    switch(act->opcode){
        case OPCODE_SUM:
        case OPCODE_SUB:
        case OPCODE_MUL:
        case OPCODE_DIV:
        case OPCODE_EWMA:
        case OPCODE_POLY_SUM:{
            //result1 is written in output
            switch((act->operand_types>>7)&1){
                case OPERAND_TYPE_FLOW_DATA_VAR:{
                    state_table_set_flow_data_variable(table, pkt, NULL, act->output, result1, act->bit);
                    break;}
                case OPERAND_TYPE_GLOBAL_DATA_VAR:{
                    table->global_data_var[act->output] = result1;
                    OFL_LOG_DBG(LOG_MODULE, "Global data variable %d updated to %"PRIu32,act->output,table->global_data_var[act->output]);
                    break;}
            }
            break;
        }
        case OPCODE_AVG:{
            //result1 is written in output
            switch((act->operand_types>>7)&1){
                case OPERAND_TYPE_FLOW_DATA_VAR:{
                    state_table_set_flow_data_variable(table, pkt, NULL, act->output, result1, act->bit);
                    break;}
                case OPERAND_TYPE_GLOBAL_DATA_VAR:{
                    table->global_data_var[act->output] = result1;
                    OFL_LOG_DBG(LOG_MODULE, "Global data variable %d updated to %"PRIu32,act->output,table->global_data_var[act->output]);
                    break;}
            }

            //result2 is written in operand_2
            switch((act->operand_types>>12)&3){
                case OPERAND_TYPE_FLOW_DATA_VAR:{
                    state_table_set_flow_data_variable(table, pkt, NULL, act->operand_2, result2, act->bit);
                    break;}
                case OPERAND_TYPE_GLOBAL_DATA_VAR:{
                    table->global_data_var[act->operand_2] = result2;
                    OFL_LOG_DBG(LOG_MODULE, "Global data variable %d updated to %"PRIu32,act->operand_2,table->global_data_var[act->operand_2]);
                    break;}
            }
            break;
        }
        case OPCODE_VAR:{
            //result1 is written in output
            switch((act->operand_types>>7)&1){
                case OPERAND_TYPE_FLOW_DATA_VAR:{
                    state_table_set_flow_data_variable(table, pkt, NULL, act->output, result1, act->bit);
                    break;}
                case OPERAND_TYPE_GLOBAL_DATA_VAR:{
                    table->global_data_var[act->output] = result1;
                    OFL_LOG_DBG(LOG_MODULE, "Global data variable %d updated to %"PRIu32,act->output,table->global_data_var[act->output]);
                    break;}
            }

            //result2 is written in operand_2
            switch((act->operand_types>>12)&3){
                case OPERAND_TYPE_FLOW_DATA_VAR:{
                    state_table_set_flow_data_variable(table, pkt, NULL, act->operand_2, result2, act->bit);
                    break;}
                case OPERAND_TYPE_GLOBAL_DATA_VAR:{
                    table->global_data_var[act->operand_2] = result2;
                    OFL_LOG_DBG(LOG_MODULE, "Global data variable %d updated to %"PRIu32,act->operand_2,table->global_data_var[act->operand_2]);
                    break;}
            }

            //result3 is written in operand_3
            switch((act->operand_types>>10)&3){
                case OPERAND_TYPE_FLOW_DATA_VAR:{
                    state_table_set_flow_data_variable(table, pkt, NULL, act->operand_3, result3, act->bit);
                    break;}
                case OPERAND_TYPE_GLOBAL_DATA_VAR:{
                    table->global_data_var[act->operand_3] = result3;
                    OFL_LOG_DBG(LOG_MODULE, "Global data variable %d updated to %"PRIu32,act->operand_3,table->global_data_var[act->operand_3]);
                    break;}
            }
            break;
        }

    }
}

ofl_err state_table_set_flow_data_variable(struct state_table *table, struct packet *pkt, struct ofl_exp_set_flow_data_variable *msg, uint8_t data_variable_id, uint32_t data_variable_value, uint8_t bit)
{
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};
    struct state_entry *e;
    uint64_t now;
    struct timeval tv;
    uint8_t flow_data_variable_id;
    uint32_t value, mask;
    int i;
    bool entry_found = 0;

    bool entry_to_update_is_cached = msg && table->last_lookup_state_entry != NULL &&
            ((bit == 0 && table->update_scope_is_eq_lookup_scope) ||
                    (bit == 1 && table->bit_update_scope_is_eq_lookup_scope));

    if (msg) {
        // SET_FLOW_DATA_VAR msg
        flow_data_variable_id = msg->flow_data_variable_id;
        value = msg->value;
        mask = msg->mask;

        if (table->update_key_extractor.key_len != msg->key_len) {
            OFL_LOG_WARN(LOG_MODULE, "update key extractor length != received key length");
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        memcpy(key, msg->key, msg->key_len);
    } else {        
        // SET_DATA_VAR action
        struct key_extractor *key_extractor_ptr;
        flow_data_variable_id = data_variable_id;
        value = data_variable_value;
        mask = 0xFFFFFFFF;

        key_extractor_ptr = (bit == 0) ? &table->update_key_extractor : &table->bit_update_key_extractor;
        if (!entry_to_update_is_cached) {
            if (!__extract_key(key, key_extractor_ptr, pkt)) {
                OFL_LOG_DBG(LOG_MODULE, "update key fields not found in the packet's header");
                return 0;
            }
        }
    }

    if (entry_to_update_is_cached) {
        OFL_LOG_DBG(LOG_MODULE, "State Table update data variable: cached state entry FOUND in hash map");
        entry_found = 1;
        e = table->last_update_state_entry;
    } else {
        HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, hmap_node,
                                hash_bytes(key, OFPSC_MAX_KEY_LEN, 0), &table->state_entries)
        {
            if (!memcmp(key, e->key, OFPSC_MAX_KEY_LEN)) {
                OFL_LOG_DBG(LOG_MODULE, "State Table update data variable: state entry FOUND in hash map");
                table->last_update_state_entry = e;
                entry_found = 1;
                break;
            }
        }
    }

    if (entry_found) {
        OFL_LOG_DBG(LOG_MODULE, "State Table update data variable: updating flow_data_var[%d]=%d",flow_data_variable_id,(e->flow_data_var[flow_data_variable_id] & (~mask)) | (value & mask));
        e->flow_data_var[flow_data_variable_id] = (e->flow_data_var[flow_data_variable_id] & (~mask)) | (value & mask);
    } else {
        // state entry is created only if the resulting entry is not a copy of the defult
        if (value != 0) {
            gettimeofday(&tv,NULL);
            now = 1000000 * tv.tv_sec + tv.tv_usec;
            e = xmalloc(sizeof(struct state_entry));
            memset(e,0,sizeof(struct state_entry));
            e->created = now;
            e->stats = xmalloc(sizeof(struct ofl_exp_state_stats));
            memset(e->stats,0,sizeof(struct ofl_exp_state_stats));
            memcpy(e->key, key, OFPSC_MAX_KEY_LEN);
            e->state = STATE_DEFAULT;
            for(i=0;i<OFPSC_MAX_FLOW_DATA_VAR_NUM;i++)
                e->flow_data_var[i]=0;
            e->flow_data_var[flow_data_variable_id] = value;

            hmap_insert(&table->state_entries, &e->hmap_node, hash_bytes(key, OFPSC_MAX_KEY_LEN, 0));
            OFL_LOG_DBG(LOG_MODULE, "State Table update data variable: creating a new state entry with flow_data_var[%d]=%d",flow_data_variable_id,e->flow_data_var[flow_data_variable_id]);

            table->last_update_state_entry = e;
        }
    }
    return 0;
}

/* State Sync:  */
ofl_err state_table_set_state(struct state_table *table, struct packet *pkt,
                           struct ofl_exp_set_flow_state *msg, struct ofl_exp_action_set_state *act,
                           struct ofl_exp_msg_notify_state_change *ntf_message)
{
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};
    struct state_entry *e;
    uint32_t state, state_mask,
            idle_rollback, hard_rollback,
            idle_timeout, hard_timeout,
            old_state, new_state;
    uint64_t now_us;
    ofl_err res = 0;
    bool entry_found = 0;
    bool entry_created = 0;
    bool entry_to_update_is_cached = act && table->last_lookup_state_entry != NULL &&
            ((act->bit == 0 && table->update_scope_is_eq_lookup_scope) ||
                    (act->bit == 1 && table->bit_update_scope_is_eq_lookup_scope));
    int i;

    if (act) {
        //SET_STATE action
        struct key_extractor *key_extractor_ptr;

        now_us = 1000000 * pkt->ts.tv_sec + pkt->ts.tv_usec;
        state = act->state;
        state_mask = act->state_mask;
        idle_rollback = act->idle_rollback;
        hard_rollback = act->hard_rollback;
        idle_timeout = act->idle_timeout;
        hard_timeout = act->hard_timeout;

        //TODO Davide: re-add hardcoded update scope

        // Bi-flow handling.
        // FIXME: rename 'bit' to something more meaningful.
        key_extractor_ptr = (act->bit == 0) ? &table->update_key_extractor : &table->bit_update_key_extractor;

        //Extract the key (we avoid to re-extract it if bit-update/update-scope == lookup-scope and the cached entry is not the default)
        if (!entry_to_update_is_cached) {
            if (!__extract_key(key, key_extractor_ptr, pkt)) {
                OFL_LOG_DBG(LOG_MODULE, "update key fields not found in the packet's header");
                return res;
            }
        }

    } else {
        //SET_STATE message - should we check if msg != null?
        struct timeval tv;

        gettimeofday(&tv,NULL);
        now_us = 1000000 * tv.tv_sec + tv.tv_usec;
        state = msg->state;
        state_mask = msg->state_mask;
        idle_rollback = msg->idle_rollback;
        hard_rollback = msg->hard_rollback;
        idle_timeout = msg->idle_timeout;
        hard_timeout = msg->hard_timeout;

        if (table->update_key_extractor.key_len != msg->key_len) {
            OFL_LOG_WARN(LOG_MODULE, "update key extractor length != received key length");
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        memcpy(key, msg->key, msg->key_len);
    }

    /*
    Look if state entry already exists in hash map.
    We avoid browsing again the hash map if bit-update/update-scope == lookup-scope, but only if
    a. we are not going to insert a new state entry (otherwise the cached state entry would be the DEFAULT one!)
    b. we are not executing a transition by a ctrl msg (there's no state lookup phase so there's no cached state entry)
    */
    if (entry_to_update_is_cached) {
        e = table->last_lookup_state_entry;
        OFL_LOG_DBG(LOG_MODULE, "State Table update state: cached state entry FOUND in hash map");
        entry_found = 1;
    } else {
        HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, hmap_node,
                                hash_bytes(key, OFPSC_MAX_KEY_LEN, 0), &table->state_entries)
        {
            if (!memcmp(key, e->key, OFPSC_MAX_KEY_LEN)) {
                OFL_LOG_DBG(LOG_MODULE, "State Table update state: state entry FOUND in hash map");
                entry_found = 1;
                break;
            }
        }
    }

    if (entry_found) {
        new_state = (e->state & ~(state_mask)) | (state & state_mask);
        old_state = e->state;
    } else {
        // Key not found in hash map.
        new_state = state & state_mask;
        old_state = STATE_DEFAULT;

        // Allocate memory only if new state is not DEFAULT or there's a timeout that will transition it to other value.
        if (new_state != STATE_DEFAULT
            || (hard_timeout > 0 && hard_rollback != STATE_DEFAULT)
            || (idle_timeout > 0 && idle_rollback != STATE_DEFAULT))
        {
            entry_created = 1;
            e = xmalloc(sizeof(struct state_entry));
            memset(e,0,sizeof(struct state_entry));
            e->stats = xmalloc(sizeof(struct ofl_exp_state_stats));
            memset(e->stats,0,sizeof(struct ofl_exp_state_stats));
            memcpy(e->key, key, OFPSC_MAX_KEY_LEN);
            hmap_insert(&table->state_entries, &e->hmap_node, hash_bytes(key, OFPSC_MAX_KEY_LEN, 0));
            OFL_LOG_DBG(LOG_MODULE, "State Table update state: state entry CREATED in hash map");
        }
    }

    if (entry_found || entry_created) {

        OFL_LOG_DBG(LOG_MODULE, "State Table update state: executing state transition to %u", new_state);

        e->state = new_state;

        // FIXME: renaming created to last_updated would be more appropriate.
        e->created = now_us;

        // Update timeouts, only if rollback state != current state
        if (hard_timeout > 0 && hard_rollback != new_state) {
            OFL_LOG_DBG(LOG_MODULE, "State Table update state: configuring hard_timeout = %u", hard_timeout);
            e->remove_at = now_us + hard_timeout;
            e->stats->hard_timeout = hard_timeout;
            e->stats->hard_rollback = hard_rollback;
        } else {
            e->stats->hard_timeout = 0;
            e->stats->hard_rollback = 0;
        }

        if (idle_timeout > 0 && idle_rollback != new_state) {
            OFL_LOG_DBG(LOG_MODULE, "State Table update state: configuring idle_timeout = %u", idle_timeout);
            e->stats->idle_timeout = idle_timeout;
            e->stats->idle_rollback = idle_rollback;
            e->last_used = now_us;
        } else {
            e->stats->idle_timeout = 0;
            e->stats->idle_rollback = 0;
        }

        // all the statistics except timeouts and rollbacks are updated on request

        #if BEBA_STATE_NOTIFICATIONS != 0
        *ntf_message = (struct ofl_exp_msg_notify_state_change)
                {{{{.type = OFPT_EXPERIMENTER},
                        .experimenter_id = BEBA_VENDOR_ID},
                        .type = OFPT_EXP_STATE_CHANGED},
                        .table_id = e->stats->table_id,
                        .old_state = old_state,
                        .new_state = new_state,
                        .state_mask = state_mask,
                        .key_len = OFPSC_MAX_KEY_LEN,
                        .key = {},
                        .flow_data_var = {}};
        memcpy(ntf_message->key, e->key, ntf_message->key_len);
        memcpy(ntf_message->flow_data_var, e->flow_data_var, OFPSC_MAX_FLOW_DATA_VAR_NUM * sizeof(uint32_t));
        #endif
    }

    return res;
}

ofl_err state_table_inc_state(struct state_table *table, struct packet *pkt){

    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};
    struct state_entry *e;
    uint64_t now_us;
    ofl_err res = 0;
    bool entry_to_update_is_cached = table->update_scope_is_eq_lookup_scope && table->last_lookup_state_entry != NULL;

    //Extract the key (we avoid to re-extract it if update-scope == lookup-scope)
    if (!entry_to_update_is_cached) {
        if (!__extract_key(key, &table->update_key_extractor, pkt)) {
            OFL_LOG_DBG(LOG_MODULE, "update key fields not found in the packet's header");
            return res;
        }

        HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, hmap_node,
                                hash_bytes(key, OFPSC_MAX_KEY_LEN, 0), &table->state_entries)
        {
            if (!memcmp(key, e->key, OFPSC_MAX_KEY_LEN)) {
                e->state += (uint32_t) 1;
                return 0;
            }
        }
    } else {
        e = table->last_lookup_state_entry;
        e->state += (uint32_t) 1;
        return 0;
    }

    now_us = 1000000 * pkt->ts.tv_sec + pkt->ts.tv_usec;
    e = xmalloc(sizeof(struct state_entry));
    e->created = now_us;
    e->stats = xmalloc(sizeof(struct ofl_exp_state_stats));
    e->stats->idle_timeout = 0;
    e->stats->hard_timeout = 0;
    e->stats->idle_rollback = 0;
    e->stats->hard_rollback = 0;
    e->state = (uint32_t) 1; // Initial condition
    memcpy(e->key, key, OFPSC_MAX_KEY_LEN);
    hmap_insert(&table->state_entries, &e->hmap_node, hash_bytes(key, OFPSC_MAX_KEY_LEN, 0));
    return 0;
}


struct ofl_action_set_field * state_table_write_context_to_field(struct state_table *table, struct ofl_exp_action_write_context_to_field *act, struct packet *pkt) {
    struct state_entry *state_entry;
    struct ofl_action_set_field *set_field_act;
    uint32_t src_value = 0;
    
    switch (act->src_type){
        case SOURCE_TYPE_FLOW_DATA_VAR:
            if (table->last_lookup_state_entry != NULL) {
                OFL_LOG_DBG(LOG_MODULE, "Retrieving flow context from lookup cache");
                state_entry = table->last_lookup_state_entry;
            } else {
                //TODO Davide: ok but if cached entry is NULL it means either the lookup returns DEF or state cannot be extracted
                // If we could distinguish between the two cases we could save another lookup in the first case.
                state_entry = state_table_lookup(table, pkt);
            }
            if(state_entry!=NULL){
                src_value = state_entry->flow_data_var[act->src_id];
            } else {
                OFL_LOG_WARN(LOG_MODULE, "ERROR WRITE CONTEXT TO FIELD at stage %u: flow_data_var cannot be found", pkt->table_id);
                return NULL;
            }
            break;
        case SOURCE_TYPE_GLOBAL_DATA_VAR:
            src_value = table->global_data_var[act->src_id];
            break;
        case SOURCE_TYPE_STATE:
            if (table->last_lookup_state_entry != NULL) {
                OFL_LOG_DBG(LOG_MODULE, "Retrieving flow context from lookup cache");
                state_entry = table->last_lookup_state_entry;
            } else {
                //TODO Davide: ok but if cached entry is NULL it means either the lookup returns DEF or state cannot be extracted
                // If we could distinguish between the two cases we could save another lookup in the first case.
                state_entry = state_table_lookup(table, pkt);
            }
            if(state_entry!=NULL){
                src_value = (uint32_t) state_entry->state;
            } else {
                OFL_LOG_WARN(LOG_MODULE, "ERROR WRITE CONTEXT TO FIELD at stage %u: state cannot be found", pkt->table_id);
                return NULL;
            }
            break;
    }
    
    // build a dummy ofl_action_set_field to re-use code from standard OpenFlow set-field action
    set_field_act = (struct ofl_action_set_field *)malloc(sizeof(struct ofl_action_set_field));
    set_field_act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
    set_field_act->field->header = act->dst_field;
    set_field_act->field->value = malloc(OXM_LENGTH(set_field_act->field->header));
    //memcpy size is min_size(src_value and dst_field)
    if (OXM_LENGTH(set_field_act->field->header)>sizeof(src_value)) {
        memcpy(set_field_act->field->value , &src_value, sizeof(src_value));
    } else {
        memcpy(set_field_act->field->value , &src_value, OXM_LENGTH(set_field_act->field->header));
    }
    
    return set_field_act;
}

ofl_err
state_table_decapsulate_gtp(struct ofl_exp_action_decapsulate_gtp *act, struct packet *pkt) {
    //packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.eth != NULL) {
        struct eth_header *eth = pkt->handle_std.proto.eth;
        //struct snap_header *eth_snap = pkt->handle_std.proto.eth_snap;
        uint16_t next_proto;

        size_t move_size = IP_HEADER_LEN + UDP_HEADER_LEN + 8; //gtp header len = 8

        if (eth->eth_type == ETH_TYPE_IP){
            next_proto = pkt->handle_std.proto.ipv4->ip_proto;
        } else if (eth->eth_type == ETH_TYPE_IPV6){
            next_proto = pkt->handle_std.proto.ipv6->ipv6_next_hd;
        } else {
            // error
        }

        if (!next_proto == IPPROTO_UDP){
            // it's not gtp 
        } else {
            uint16_t dst_port = pkt->handle_std.proto.udp->udp_dst;
            if (htons(dst_port) != 2152){

            } //not gtp encap

            else {
                pkt->buffer->data = (uint8_t *)pkt->buffer->data + move_size;
                pkt->buffer->size -= move_size;

                memmove(pkt->buffer->data, eth, ETH_HEADER_LEN); //eth header len

                pkt->handle_std.valid = false;
            }
        }
    } else {
        //VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute GTP_DECAP action on packet with no eth.");
    }

    return 0;
}

ofl_err
state_table_soft_decapsulate_gtp(struct ofl_exp_action_soft_decapsulate_gtp *act, struct packet *pkt) {
    //packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.eth != NULL) {
        struct eth_header *eth = pkt->handle_std.proto.eth;
        //struct snap_header *eth_snap = pkt->handle_std.proto.eth_snap;
        uint16_t next_proto;
        struct ip_header *ipv4;
        struct udp_header *udp;
        struct tcp_header *tcp;

        size_t move_size = IP_HEADER_LEN + UDP_HEADER_LEN + 8; //gtp header len = 8

        if (eth->eth_type == ETH_TYPE_IP){
            next_proto = pkt->handle_std.proto.ipv4->ip_proto;
        } else if (eth->eth_type == ETH_TYPE_IPV6){
            next_proto = pkt->handle_std.proto.ipv6->ipv6_next_hd;
        } else {
            // error
        }
        if (!next_proto == IPPROTO_UDP){
            // it's not gtp encap
        } else {
            uint16_t dst_port = pkt->handle_std.proto.udp->udp_dst;
            if (htons(dst_port) != 2152){

            } //not gtp encap

            else {
                soft_decap_parsing = true;
                pkt->handle_std.valid = false;
                return 0;
            }
        }
    } else {
        //VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute GTP_DECAP action on packet with no eth.");
    }

    return 0;
}

ofl_err
state_table_encapsulate_gtp(struct ofl_exp_action_encapsulate_gtp *act, struct packet *pkt){
    if (pkt->handle_std.proto.eth != NULL){
        size_t encap_size = IP_HEADER_LEN + UDP_HEADER_LEN + 8;
        struct pkttmp_table *t = pkt->dp->pkttmps;
        struct pkttmp_entry *pkttmp;
        uint8_t found = 0;
        struct eth_header *eth = pkt->handle_std.proto.eth;

        /*if (ofpbuf_headroom(pkt->buffer) >= encap_size) {
            pkt->buffer->data = (uint8_t *)(pkt->buffer->data) - encap_size;
            pkt->buffer->size += encap_size;

            fprintf(stderr, "headroom: %zu\n", ofpbuf_headroom(pkt->buffer));

            memmove(pkt->buffer->data, eth, ETH_HEADER_LEN); //move backwards eth

        } else { */ //tailroom
            ofpbuf_put_uninit(pkt->buffer, encap_size);

            memmove((uint8_t *) pkt->buffer->data + encap_size + ETH_HEADER_LEN,
                    (uint8_t *) pkt->buffer->data + ETH_HEADER_LEN,
                    pkt->buffer->size - ETH_HEADER_LEN);
        //}

        HMAP_FOR_EACH_WITH_HASH(pkttmp, struct pkttmp_entry, node,
                                    act->pkttmp_id, &t->entries) 
        {
            found = 1;

            memcpy(pkt->buffer->data + ETH_HEADER_LEN, pkttmp->data, encap_size);
        }
        if (!found) {
            return -1; //error
        }

        struct ip_header *ipv4 = (struct ip_header *)((uint8_t const *) pkt->buffer->data + ETH_HEADER_LEN);
        struct udp_header *udp = (struct udp_header *)((uint8_t const *) ipv4 + IP_HEADER_LEN);

        ipv4->ip_tot_len = htons(pkt->buffer->size - ETH_HEADER_LEN);
        udp->udp_len = htons(pkt->buffer->size - ETH_HEADER_LEN - IP_HEADER_LEN);

        uint8_t *gtp_message_type = (uint8_t const *) pkt->buffer->data + ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 1;
        *gtp_message_type = 0xff;

        uint16_t *gtp_len = (uint8_t const *) pkt->buffer->data + ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + 1 + 1;
        *gtp_len = htons(pkt->buffer->size - ETH_HEADER_LEN - encap_size);


    } else {
        // error no eth in pkt
    }
    return 0;
}

/*
 * State Sync: One extra argument (i.e., ntf_message) is passed to this function to notify about
 * a state change in the state table.
 */
ofl_err
handle_state_mod(struct pipeline *pl, struct ofl_exp_msg_state_mod *msg,
                const struct sender *sender UNUSED, struct ofl_exp_msg_notify_state_change * ntf_message) {
    switch (msg->command){
        case OFPSC_STATEFUL_TABLE_CONFIG:{
            struct ofl_exp_stateful_table_config *p = (struct ofl_exp_stateful_table_config *) msg->payload;
            struct state_table *st = pl->tables[p->table_id]->state_table;
            return state_table_configure_stateful(st, p->stateful);
            break;}

        case OFPSC_EXP_SET_L_EXTRACTOR:
        case OFPSC_EXP_SET_U_EXTRACTOR:{
            struct ofl_exp_set_extractor *p = (struct ofl_exp_set_extractor *) msg->payload;
            struct state_table *st = pl->tables[p->table_id]->state_table;
            if (st->stateful){
                int update = 0;
                if (msg->command == OFPSC_EXP_SET_U_EXTRACTOR)
                    update = 1;
                return state_table_set_extractor(st, (struct key_extractor *)p, update);
            }
            else{
                OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD: cannot configure extractor (stage %u is not stateful)", p->table_id);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_SET_EXTRACTOR);
            }
            break;}

        case OFPSC_EXP_SET_FLOW_STATE:{
            struct ofl_exp_set_flow_state *p = (struct ofl_exp_set_flow_state *) msg->payload;
            struct state_table *st = pl->tables[p->table_id]->state_table;
            // State Sync: Now state_table_set_state function contains this extra parameter related to the
            // state notification.
            if (state_table_is_enabled(st)){
                return state_table_set_state(st, NULL, p, NULL, ntf_message);
            }
            else{
                OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD at stage %u: stage not stateful or not configured", p->table_id);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_SET_FLOW_STATE);
            }
            break;}

        case OFPSC_EXP_DEL_FLOW_STATE:{
            struct ofl_exp_del_flow_state *p = (struct ofl_exp_del_flow_state *) msg->payload;
            struct state_table *st = pl->tables[p->table_id]->state_table;
            if (state_table_is_enabled(st)){
                return state_table_del_state(st, p->key, p->key_len);
            }
            else{
                OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD at stage %u: stage not stateful or not configured", p->table_id);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_DEL_FLOW_STATE);
            }
            break;}

        case OFPSC_EXP_SET_GLOBAL_STATE:{
            uint32_t global_state = pl->dp->global_state;
            struct ofl_exp_set_global_state *p = (struct ofl_exp_set_global_state *) msg->payload;
            global_state = (global_state & ~(p->global_state_mask)) | (p->global_state & p->global_state_mask);
            pl->dp->global_state = global_state;
            return 0;
            break;}

        case OFPSC_EXP_RESET_GLOBAL_STATE:{
            pl->dp->global_state = OFP_GLOBAL_STATE_DEFAULT;
            return 0;
            break;}
        case OFPSC_EXP_SET_HEADER_FIELD_EXTRACTOR:{
            struct ofl_exp_set_header_field_extractor *p = (struct ofl_exp_set_header_field_extractor *) msg->payload;
            struct state_table *st = pl->tables[p->table_id]->state_table;
            if (state_table_is_enabled(st)){
                return state_table_set_header_field_extractor(st, p);
            }
            else{
                OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD at stage %u: stage not stateful", p->table_id);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_HEADER_EXTRACTOR);
            }
            
            break;}
        case OFPSC_EXP_SET_CONDITION:{
            struct ofl_exp_set_condition *p = (struct ofl_exp_set_condition *) msg->payload;
            struct state_table *st = pl->tables[p->table_id]->state_table;
            if (state_table_is_enabled(st)){
                return state_table_set_condition(st, p); 
            }
            else{
                OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD at stage %u: stage not stateful", p->table_id);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_CONDITION);
            }
            break;}
        case OFPSC_EXP_SET_GLOBAL_DATA_VAR:{
            struct ofl_exp_set_global_data_variable *p = (struct ofl_exp_set_global_data_variable *) msg->payload;
            struct state_table *st = pl->tables[p->table_id]->state_table;
            if (state_table_is_enabled(st)){
                uint32_t global_data_var = st->global_data_var[p->global_data_variable_id];
                global_data_var = (global_data_var & ~(p->mask)) | (p->value & p->mask);
                st->global_data_var[p->global_data_variable_id] = global_data_var;
                OFL_LOG_DBG(LOG_MODULE, "Global data variable %u configured to value %d",p->global_data_variable_id,st->global_data_var[p->global_data_variable_id]);
            }
            else{
                OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD at stage %u: stage not stateful", p->table_id);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_CONDITION);
            }
            break;}
        case OFPSC_EXP_SET_FLOW_DATA_VAR:{
            struct ofl_exp_set_flow_data_variable *p = (struct ofl_exp_set_flow_data_variable *) msg->payload;
            struct state_table *st = pl->tables[p->table_id]->state_table;
            if (state_table_is_enabled(st)){
                return state_table_set_flow_data_variable(st, NULL, p, 0, 0, 0);
            }
            else{
                OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD at stage %u: stage not stateful or not configured", p->table_id);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_SET_FLOW_STATE);
            }
            break;}
        default:
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_STATE_MOD_FAILED);
    }

    return 0;
}

ofl_err
handle_pkttmp_mod(struct pipeline *pl, struct ofl_exp_msg_pkttmp_mod *msg,
                                                const struct sender *sender UNUSED) {
    OFL_LOG_DBG(LOG_MODULE, "Handling PKTTMP_MOD");
    /* TODO: complete handling of creating and deleting pkttmp entry */
    switch (msg->command){
        case OFPSC_ADD_PKTTMP:{
            struct ofl_exp_add_pkttmp *p = (struct ofl_exp_add_pkttmp *) msg->payload;
            struct pkttmp_entry *e;
            e = pkttmp_entry_create(pl->dp, pl->dp->pkttmps, p);

            hmap_insert(&pl->dp->pkttmps->entries, &e->node, e->pkttmp_id);
            OFL_LOG_DBG(LOG_MODULE, "PKTTMP id is %d, inserted to hash map", e->pkttmp_id);
            break;}

        default:
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_PKTTMP_MOD_FAILED);
    }
    return 0;
}

ofl_err
handle_stats_request_state(struct pipeline *pl, struct ofl_exp_msg_multipart_request_state *msg, const struct sender *sender UNUSED, struct ofl_exp_msg_multipart_reply_state *reply) {
    struct ofl_exp_state_stats **stats = xmalloc(sizeof(struct ofl_exp_state_stats *));
    size_t stats_size = 1;
    size_t stats_num = 0;
    if (msg->table_id == 0xff) {
        size_t i;
        for (i=0; i<PIPELINE_TABLES; i++) {
            if (state_table_is_enabled(pl->tables[i]->state_table))
                state_table_stats(pl->tables[i]->state_table, msg, &stats, &stats_size, &stats_num, i, msg->header.type == OFPMP_EXP_STATE_STATS_AND_DELETE);
        }
    } else {
        if (state_table_is_enabled(pl->tables[msg->table_id]->state_table))
            state_table_stats(pl->tables[msg->table_id]->state_table, msg, &stats, &stats_size, &stats_num, msg->table_id, msg->header.type == OFPMP_EXP_STATE_STATS_AND_DELETE);
    }
    *reply = (struct ofl_exp_msg_multipart_reply_state)
            {{{{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_EXPERIMENTER, .flags = 0x0000},
             .experimenter_id = BEBA_VENDOR_ID},
             .type = msg->header.type},
             .stats = stats,
             .stats_num = stats_num};
    return 0;
}

ofl_err
handle_stats_request_global_state(struct pipeline *pl, const struct sender *sender UNUSED, struct ofl_exp_msg_multipart_reply_global_state *reply) {
    uint32_t global_state = pl->dp->global_state;

    *reply = (struct ofl_exp_msg_multipart_reply_global_state)
            {{{{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_EXPERIMENTER, .flags = 0x0000},
             .experimenter_id = BEBA_VENDOR_ID},
             .type = OFPMP_EXP_GLOBAL_STATE_STATS},
             .global_state = global_state};
    return 0;
}

void
state_table_stats(struct state_table *table, struct ofl_exp_msg_multipart_request_state *msg,
                 struct ofl_exp_state_stats ***stats, size_t *stats_size, size_t *stats_num, uint8_t table_id, bool delete_entries)
{
    struct state_entry *entry, *next;
    size_t  i;
    uint32_t fields[OFPSC_MAX_FIELD_COUNT] = {0};
    struct timeval tv;
    gettimeofday(&tv,NULL);
    uint64_t now_us = 1000000 * tv.tv_sec + tv.tv_usec;
    struct key_extractor *extractor=&table->lookup_key_extractor;

    struct ofl_match const * a = (struct ofl_match const *)msg->match;
    struct ofl_match_tlv *state_key_match;
    uint8_t count = 0;
    uint8_t found = 0;
    uint8_t len = 0;
    uint8_t aux = 0;

    uint8_t offset[OFPSC_MAX_FIELD_COUNT] = {0};
    uint8_t length[OFPSC_MAX_FIELD_COUNT] = {0};


    for (i=0; i<extractor->field_count; i++) {
        fields[i] = (int)extractor->fields[i];
     }

    //for each received match_field we must verify if it can be found in the key extractor and (if yes) save its position in the key (offset) and its length
    HMAP_FOR_EACH(state_key_match, struct ofl_match_tlv, hmap_node, &a->match_fields)
    {
        len = 0;
        found = 0;
        for (i=0;i<extractor->field_count;i++)
        {
                if(OXM_TYPE(state_key_match->header)==OXM_TYPE(fields[i]))
                {
                    offset[count] = len;
                    length[count] = OXM_LENGTH(fields[i]);
                    count++;
                    found = 1;
                    break;
                }
                len += OXM_LENGTH(fields[i]);
        }
        if(!found)
            return; //If at least one of the received match_field is not found in the key extractor, the function returns an empty list of entries
    }

    //for each state entry
    HMAP_FOR_EACH_SAFE(entry, next, struct state_entry, hmap_node, &table->state_entries) {
        if(entry == NULL)
            break;

        //for each received match_field compare the received value with the state entry's key
        aux = 0;
        found = 1;
        HMAP_FOR_EACH(state_key_match, struct ofl_match_tlv, hmap_node, &a->match_fields)
        {
            if(memcmp(state_key_match->value,&entry->key[offset[aux]], length[aux]))
                found = 0;
            aux+=1;
        }

        state_entry_apply_hard_timeout(entry, now_us);
        state_entry_apply_idle_timeout(entry, now_us);

        if(found && ((msg->get_from_state && msg->state == entry->state) || (!msg->get_from_state)))
        {
            if ((*stats_size) == (*stats_num)) {
                (*stats) = xrealloc(*stats, (sizeof(struct ofl_exp_state_stats *)) * (*stats_size) * 2);
                *stats_size *= 2;
            }

            // entry->stats are referenced by the reply message, NOT copied
            (*stats)[(*stats_num)] = entry->stats;
            (*stats)[(*stats_num)]->table_id = table_id;
            (*stats)[(*stats_num)]->duration_sec = (now_us - entry->created) / 1000000;
            (*stats)[(*stats_num)]->duration_nsec = ((now_us - entry->created) % 1000000) * 1000;
            (*stats)[(*stats_num)]->field_count = extractor->field_count;
            memcpy((*stats)[(*stats_num)]->fields, extractor->fields, sizeof(uint32_t) * extractor->field_count);
            // timeouts and rollbacks have been already set

            (*stats)[(*stats_num)]->entry.state = entry->state;
            memcpy((*stats)[(*stats_num)]->entry.key, entry->key, extractor->key_len);
            (*stats)[(*stats_num)]->entry.key_len = extractor->key_len;
            memcpy((*stats)[(*stats_num)]->entry.flow_data_var, entry->flow_data_var, sizeof(uint32_t)*OFPSC_MAX_FLOW_DATA_VAR_NUM);

            (*stats_num)++;

            if (delete_entries){
                // state_entries are removed from hmap but entry->stats are freed only after reply msg has been sent
                // because the reply message contains references to entry->stats!
                hmap_remove_and_shrink(&table->state_entries, &entry->hmap_node);
                free(entry);
            }
        }
    }

     /*DEFAULT ENTRY*/
    if(!msg->get_from_state || (msg->get_from_state && msg->state == STATE_DEFAULT))
    {
        if ((*stats_size) == (*stats_num)) {
            (*stats) = xrealloc(*stats, (sizeof(struct ofl_exp_state_stats *)) * (*stats_size) * 2);
            *stats_size *= 2;
        }
        (*stats)[(*stats_num)] = table->default_state_entry.stats;

        (*stats_num)++;
    }
}

size_t
ofl_structs_state_stats_ofp_len(struct ofl_exp_state_stats *stats UNUSED, struct ofl_exp const *exp UNUSED)
{
    return ROUND_UP((sizeof(struct ofp_exp_state_stats)),8);
}

size_t
ofl_structs_state_stats_ofp_total_len(struct ofl_exp_state_stats ** stats UNUSED, size_t stats_num, struct ofl_exp const *exp UNUSED)
{
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN2(sum, stats, stats_num,
            ofl_structs_state_stats_ofp_len, exp);
    return sum;
}

size_t
ofl_structs_state_stats_pack(struct ofl_exp_state_stats const *src, uint8_t *dst, struct ofl_exp const *exp UNUSED)
{
    struct ofp_exp_state_stats *state_stats;
    size_t total_len;
    size_t  i;
    total_len = ROUND_UP(sizeof(struct ofp_exp_state_stats),8);
    state_stats = (struct ofp_exp_state_stats*) dst;
    memset(state_stats, 0, sizeof(struct ofp_exp_state_stats));
    state_stats->length = htons(total_len);
    state_stats->table_id = src->table_id;
    state_stats->duration_sec = htonl(src->duration_sec);
    state_stats->duration_nsec = htonl(src->duration_nsec);

    state_stats->pad = 0;

    state_stats->field_count = htonl(src->field_count);
    memset(state_stats->fields,0x00,sizeof(uint32_t)*OFPSC_MAX_FIELD_COUNT);
    for (i=0;i<src->field_count;i++)
           state_stats->fields[i]=htonl(src->fields[i]);

    state_stats->entry.key_len = htonl(src->entry.key_len);
    memset(state_stats->entry.key,0x00,sizeof(uint8_t)*OFPSC_MAX_KEY_LEN);
    memcpy(state_stats->entry.key, src->entry.key, src->entry.key_len);

    for(i=0;i<OFPSC_MAX_FLOW_DATA_VAR_NUM;i++)
        state_stats->entry.flow_data_var[i] = htonl(src->entry.flow_data_var[i]);

    state_stats->entry.state = htonl(src->entry.state);
    state_stats->idle_timeout = htonl(src->idle_timeout);
    state_stats->idle_rollback = htonl(src->idle_rollback);
    state_stats->hard_timeout = htonl(src->hard_timeout);
    state_stats->hard_rollback = htonl(src->hard_rollback);
    return total_len;
}

void
ofl_structs_state_entry_print(FILE *stream, uint32_t field, uint8_t *key, uint8_t *offset)
{

    switch (OXM_FIELD(field)) {

        case OFPXMT_OFB_IN_PORT:
            fprintf(stream, "in_port=\"%d\"", *((uint32_t*) key));
            break;
        case OFPXMT_OFB_IN_PHY_PORT:
            fprintf(stream, "in_phy_port=\"%d\"", *((uint32_t*) key));
            break;
        case OFPXMT_OFB_VLAN_VID: {
            uint16_t v = *((uint16_t *) key);
            fprintf(stream, "vlan_vid=\"%d\"",v & VLAN_VID_MASK);
            break;
        }
        case OFPXMT_OFB_VLAN_PCP:
            fprintf(stream, "vlan_pcp=\"%d\"", *key & 0x7);
            break;
        case OFPXMT_OFB_METADATA: {
            fprintf(stream, "metadata=\"0x%"PRIx64"\"", *((uint64_t*) key));
            break;
        }
        case OFPXMT_OFB_ETH_TYPE:
            fprintf(stream, "eth_type=\"0x%x\"",  *((uint16_t *) key));
            break;
        case OFPXMT_OFB_TCP_SRC:
            fprintf(stream, "tcp_src=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_TCP_DST:
            fprintf(stream, "tcp_dst=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_TCP_FLAGS:
            fprintf(stream,"tcp_flags=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_UDP_SRC:
            fprintf(stream, "udp_src=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_UDP_DST:
            fprintf(stream, "udp_dst=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_SCTP_SRC:
            fprintf(stream, "sctp_src=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_SCTP_DST:
            fprintf(stream, "sctp_dst=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_ETH_SRC:
            fprintf(stream, "eth_src=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(key));
            break;
        case OFPXMT_OFB_ETH_DST:
            fprintf(stream, "eth_dst=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(key));
            break;
        case OFPXMT_OFB_IPV4_DST:
            fprintf(stream, "ipv4_dst=\""IP_FMT"\"", IP_ARGS(key));
            break;
        case OFPXMT_OFB_IPV4_SRC:
            fprintf(stream, "ipv4_src=\""IP_FMT"\"", IP_ARGS(key));
            break;
        case OFPXMT_OFB_IP_PROTO:
            fprintf(stream, "ip_proto=\"%d\"", *key);
            break;
        case OFPXMT_OFB_IP_DSCP:
            fprintf(stream, "ip_dscp=\"%d\"", *key & 0x3f);
            break;
        case OFPXMT_OFB_IP_ECN:
            fprintf(stream, "ip_ecn=\"%d\"", *key & 0x3);
            break;
        case OFPXMT_OFB_ICMPV4_TYPE:
            fprintf(stream, "icmpv4_type= \"%d\"", *key);
            break;
        case OFPXMT_OFB_ICMPV4_CODE:
            fprintf(stream, "icmpv4_code=\"%d\"", *key);
            break;
        case OFPXMT_OFB_ARP_SHA:
            fprintf(stream, "arp_sha=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(key));
            break;
        case OFPXMT_OFB_ARP_THA:
            fprintf(stream, "arp_tha=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(key));
            break;
        case OFPXMT_OFB_ARP_SPA:
            fprintf(stream, "arp_spa=\""IP_FMT"\"", IP_ARGS(key));
            break;
        case OFPXMT_OFB_ARP_TPA:
            fprintf(stream, "arp_tpa=\""IP_FMT"\"", IP_ARGS(key));
            break;
        case OFPXMT_OFB_ARP_OP:
            fprintf(stream, "arp_op=\"0x%x\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_IPV6_SRC: {
            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, key, addr_str, INET6_ADDRSTRLEN);
            fprintf(stream, "nw_src_ipv6=\"%s\"", addr_str);
            break;
        }
        case OFPXMT_OFB_IPV6_DST: {
            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, key, addr_str, INET6_ADDRSTRLEN);
            fprintf(stream, "nw_dst_ipv6=\"%s\"", addr_str);
            break;
        }
        case OFPXMT_OFB_IPV6_ND_TARGET: {
            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, key, addr_str, INET6_ADDRSTRLEN);
            fprintf(stream, "ipv6_nd_target=\"%s\"", addr_str);
            break;
        }
        case OFPXMT_OFB_IPV6_ND_SLL:
            fprintf(stream, "ipv6_nd_sll=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(key));
            break;
        case OFPXMT_OFB_IPV6_ND_TLL:
            fprintf(stream, "ipv6_nd_tll=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(key));
            break;
        case OFPXMT_OFB_IPV6_FLABEL:
            fprintf(stream, "ipv6_flow_label=\"%d\"", *((uint32_t*) key) & 0x000fffff);
            break;
        case OFPXMT_OFB_ICMPV6_TYPE:
            fprintf(stream, "icmpv6_type=\"%d\"", *key);
            break;
        case OFPXMT_OFB_ICMPV6_CODE:
            fprintf(stream, "icmpv6_code=\"%d\"", *key);
            break;
        case OFPXMT_OFB_MPLS_LABEL:
            fprintf(stream, "mpls_label=\"%d\"",((uint32_t) *key) & 0x000fffff);
            break;
        case OFPXMT_OFB_MPLS_TC:
            fprintf(stream, "mpls_tc=\"%d\"", *key & 0x3);
            break;
        case OFPXMT_OFB_MPLS_BOS:
            fprintf(stream, "mpls_bos=\"%d\"", *key & 0x1);
            break;
        case OFPXMT_OFB_PBB_ISID   :
            fprintf(stream, "pbb_isid=\"%d\"", *((uint32_t*) key));
            break;
        case OFPXMT_OFB_TUNNEL_ID:
            fprintf(stream, "tunnel_id=\"%"PRIu64"\"", *((uint64_t*) key));
            break;
        case OFPXMT_OFB_IPV6_EXTHDR:
            fprintf(stream, "ext_hdr=\"");
            ofl_ipv6_ext_hdr_print(stream, *((uint16_t*) key));
            fprintf(stream, "\"");
            break;
        default:
            fprintf(stream, "unknown type %d", field);
    }
    *offset += OXM_LENGTH(field);
}

void
ofl_structs_state_entry_print_default(FILE *stream, uint32_t field)
{

    switch (OXM_FIELD(field)) {

        case OFPXMT_OFB_IN_PORT:
            fprintf(stream, "in_port=\"*\"");
            break;
        case OFPXMT_OFB_IN_PHY_PORT:
            fprintf(stream, "in_phy_port=\"*\"");
            break;
        case OFPXMT_OFB_VLAN_VID:
            fprintf(stream, "vlan_vid=\"*\"");
            break;
        case OFPXMT_OFB_VLAN_PCP:
            fprintf(stream, "vlan_pcp=\"*\"");
            break;
        case OFPXMT_OFB_METADATA:
            fprintf(stream, "metadata=\"*\"");
            break;
        case OFPXMT_OFB_ETH_TYPE:
            fprintf(stream, "eth_type=\"*\"");
            break;
        case OFPXMT_OFB_TCP_SRC:
            fprintf(stream, "tcp_src=\"*\"");
            break;
        case OFPXMT_OFB_TCP_DST:
            fprintf(stream, "tcp_dst=\"*\"");
            break;
        case OFPXMT_OFB_TCP_FLAGS:
            fprintf(stream,"tcp_flags=\"*\"");
            break;
        case OFPXMT_OFB_UDP_SRC:
            fprintf(stream, "udp_src=\"*\"");
            break;
        case OFPXMT_OFB_UDP_DST:
            fprintf(stream, "udp_dst=\"*\"");
            break;
        case OFPXMT_OFB_SCTP_SRC:
            fprintf(stream, "sctp_src=\"*\"");
            break;
        case OFPXMT_OFB_SCTP_DST:
            fprintf(stream, "sctp_dst=\"*\"");
            break;
        case OFPXMT_OFB_ETH_SRC:
            fprintf(stream, "eth_src=\"*\"");
            break;
        case OFPXMT_OFB_ETH_DST:
            fprintf(stream, "eth_dst=\"*\"");
            break;
        case OFPXMT_OFB_IPV4_DST:
            fprintf(stream, "ipv4_dst=\"*\"");
            break;
        case OFPXMT_OFB_IPV4_SRC:
            fprintf(stream, "ipv4_src=\"*\"");
            break;
        case OFPXMT_OFB_IP_PROTO:
            fprintf(stream, "ip_proto=\"*\"");
            break;
        case OFPXMT_OFB_IP_DSCP:
            fprintf(stream, "ip_dscp=\"*\"");
            break;
        case OFPXMT_OFB_IP_ECN:
            fprintf(stream, "ip_ecn=\"*\"");
            break;
        case OFPXMT_OFB_ICMPV4_TYPE:
            fprintf(stream, "icmpv4_type= \"*\"");
            break;
        case OFPXMT_OFB_ICMPV4_CODE:
            fprintf(stream, "icmpv4_code=\"*\"");
            break;
        case OFPXMT_OFB_ARP_SHA:
            fprintf(stream, "arp_sha=\"*\"");
            break;
        case OFPXMT_OFB_ARP_THA:
            fprintf(stream, "arp_tha=\"*\"");
            break;
        case OFPXMT_OFB_ARP_SPA:
            fprintf(stream, "arp_spa=\"*\"");
            break;
        case OFPXMT_OFB_ARP_TPA:
            fprintf(stream, "arp_tpa=\"*\"");
            break;
        case OFPXMT_OFB_ARP_OP:
            fprintf(stream, "arp_op=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_SRC:
            fprintf(stream, "nw_src_ipv6=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_DST:
            fprintf(stream, "nw_dst_ipv6=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_ND_TARGET:
            fprintf(stream, "ipv6_nd_target=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_ND_SLL:
            fprintf(stream, "ipv6_nd_sll=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_ND_TLL:
            fprintf(stream, "ipv6_nd_tll=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_FLABEL:
            fprintf(stream, "ipv6_flow_label=\"*\"");
            break;
        case OFPXMT_OFB_ICMPV6_TYPE:
            fprintf(stream, "icmpv6_type=\"*\"");
            break;
        case OFPXMT_OFB_ICMPV6_CODE:
            fprintf(stream, "icmpv6_code=\"*\"");
            break;
        case OFPXMT_OFB_MPLS_LABEL:
            fprintf(stream, "mpls_label=\"*\"");
            break;
        case OFPXMT_OFB_MPLS_TC:
            fprintf(stream, "mpls_tc=\"*\"");
            break;
        case OFPXMT_OFB_MPLS_BOS:
            fprintf(stream, "mpls_bos=\"*\"");
            break;
        case OFPXMT_OFB_PBB_ISID   :
            fprintf(stream, "pbb_isid=\"*\"");
            break;
        case OFPXMT_OFB_TUNNEL_ID:
            fprintf(stream, "tunnel_id=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_EXTHDR:
            fprintf(stream, "ext_hdr=\"*\"");
            fprintf(stream, "\"");
            break;
        default:
            fprintf(stream, "unknown type %d", field);
    }
}

void
ofl_structs_state_stats_print(FILE *stream, struct ofl_exp_state_stats *s, struct ofl_exp const *exp UNUSED)
{
    int i;
    uint8_t offset=0;
    if(ofl_colored_output())
    {
        fprintf(stream, "{\x1B[31mtable\x1B[0m=\"");
        ofl_table_print(stream, s->table_id);
        fprintf(stream, "\", \x1B[31mkey\x1B[0m={");

        for(i=0;i<s->field_count;i++)
        {
            if(s->entry.key_len==0)
                ofl_structs_state_entry_print_default(stream,s->fields[i]);
            else
                ofl_structs_state_entry_print(stream,s->fields[i], s->entry.key+offset, &offset);
            if (s->field_count!=1 && i<s->field_count-1)
                fprintf(stream, ", ");
        }
        fprintf(stream, "}, \x1B[31mstate\x1B[0m=\"");
        fprintf(stream, "%"PRIu32"\"", s->entry.state);
        for (i=0;i<OFPSC_MAX_FLOW_DATA_VAR_NUM;i++){
            fprintf(stream, ",flow_data_var_%d=\"%"PRIu32"\"", i, s->entry.flow_data_var[i]);
        }
        if(s->entry.key_len!=0)
            fprintf(stream, ", dur_s=\"%u\", dur_ns=\"%09u\", idle_to=\"%u\", idle_rb=\"%u\", hard_to=\"%u\", hard_rb=\"%u\"",s->duration_sec, s->duration_nsec, s->idle_timeout, s->idle_rollback, s->hard_timeout, s->hard_rollback);
    }

    else
    {
        fprintf(stream, "{table=\"");
        ofl_table_print(stream, s->table_id);
        fprintf(stream, "\", key={");

        for(i=0;i<s->field_count;i++)
        {
            if(s->entry.key_len==0)
                ofl_structs_state_entry_print_default(stream,s->fields[i]);
            else
                ofl_structs_state_entry_print(stream,s->fields[i], s->entry.key+offset, &offset);
            if (s->field_count!=1 && i<s->field_count-1)
                fprintf(stream, ", ");
        }
        fprintf(stream, "}, state=\"");
        fprintf(stream, "%"PRIu32"\"", s->entry.state);
        for (i=0;i<OFPSC_MAX_FLOW_DATA_VAR_NUM;i++){
            fprintf(stream, ",flow_data_var_%d=\"%"PRIu32"\"", i, s->entry.flow_data_var[i]);
        }
        if(s->entry.key_len!=0)
            fprintf(stream, ", dur_s=\"%u\", dur_ns=\"%09u\", idle_to=\"%u\", idle_rb=\"%u\", hard_to=\"%u\", hard_rb=\"%u\"",s->duration_sec, s->duration_nsec, s->idle_timeout, s->idle_rollback, s->hard_timeout, s->hard_rollback);
    }

    fprintf(stream, "}");
}

ofl_err
ofl_structs_state_stats_unpack(struct ofp_exp_state_stats const *src, uint8_t const *buf UNUSED, size_t *len, struct ofl_exp_state_stats **dst, struct ofl_exp const *exp UNUSED)
{
    struct ofl_exp_state_stats *s;
    size_t slen;
    size_t i;
    if (*len < sizeof(struct ofp_exp_state_stats) ) {
        OFL_LOG_WARN(LOG_MODULE, "Received state stats has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (*len < ntohs(src->length)) {
        OFL_LOG_WARN(LOG_MODULE, "Received state stats reply has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (src->table_id >= PIPELINE_TABLES) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ts = ofl_table_to_string(src->table_id);
            OFL_LOG_WARN(LOG_MODULE, "Received state stats has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
    }

    slen = ntohs(src->length) - sizeof(struct ofp_exp_state_stats);

    s = (struct ofl_exp_state_stats *)malloc(sizeof(struct ofl_exp_state_stats));
    s->table_id =  src->table_id;
    s->duration_sec = ntohl(src->duration_sec);
    s->duration_nsec = ntohl(src->duration_nsec);
    s->field_count = ntohl(src->field_count);
    for (i=0;i<s->field_count;i++)
               s->fields[i]=ntohl(src->fields[i]);

    s->entry.key_len = ntohl(src->entry.key_len);
    for (i=0;i<s->entry.key_len;i++)
               s->entry.key[i]=src->entry.key[i];
    s->entry.state = ntohl(src->entry.state);
    for(i=0;i<OFPSC_MAX_FLOW_DATA_VAR_NUM;i++)
        s->entry.flow_data_var[i] = ntohl(src->entry.flow_data_var[i]);

    s->idle_timeout = ntohl(src->idle_timeout);
    s->idle_rollback = ntohl(src->idle_rollback);
    s->hard_timeout = ntohl(src->hard_timeout);
    s->hard_rollback = ntohl(src->hard_rollback);

    if (slen != 0) {
        *len = *len - ntohs(src->length) + slen;
        OFL_LOG_WARN(LOG_MODULE, "The received state stats contained extra bytes (%zu).", slen);
        free(s);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= ntohs(src->length);
    *dst = s;
    return 0;
}

ofl_err
ofl_utils_count_ofp_state_stats(void *data, size_t data_len, size_t *count)
{
    struct ofp_exp_state_stats *stat;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;
    while (data_len >= sizeof(struct ofp_exp_state_stats)) {
        stat = (struct ofp_exp_state_stats *)d;
        if (data_len < ntohs(stat->length) || ntohs(stat->length) < sizeof(struct ofp_exp_state_stats)) {
            OFL_LOG_WARN(LOG_MODULE, "Received state stat has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(stat->length);
        d += ntohs(stat->length);
        (*count)++;
    }

    return 0;
}

void
ofl_exp_stats_type_print(FILE *stream, uint32_t type)
{
    switch (type) {
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS):          { fprintf(stream, "state"); return; }
        case (OFPMP_EXP_GLOBAL_STATE_STATS):          { fprintf(stream, "global_state"); return; }
        default: {                    fprintf(stream, "?(%u)", type); return; }
    }
}


/*Functions used by experimenter match fields*/

struct ofl_match_tlv *
ofl_structs_match_exp_put8(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint8_t value)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + 4;
    return m;
}

struct ofl_match_tlv *
ofl_structs_match_exp_put8m(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint8_t value, uint8_t mask)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + sizeof(mask) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    memcpy(m->value + EXP_ID_LEN + sizeof(value), &mask, sizeof(mask));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + sizeof(mask) + 4;
    return m;
}

struct ofl_match_tlv *
ofl_structs_match_exp_put16(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint16_t value)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + 4;
    return m;
}

struct ofl_match_tlv *
ofl_structs_match_exp_put16m(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint16_t value, uint16_t mask)
{
	struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value)+sizeof(mask) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    memcpy(m->value + EXP_ID_LEN + sizeof(value), &mask, sizeof(mask));
    hmap_insert(&match->match_fields,&m->hmap_node,hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + sizeof(mask) + 4;
    return m;
}

// TODO: functions like ofl_structs_match_exp_put32 are not related to BEBA, move somewhere else.
struct ofl_match_tlv *
ofl_structs_match_exp_put32(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint32_t value)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + 4;
    return m;
}

struct ofl_match_tlv *
ofl_structs_match_exp_put32m(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint32_t value, uint32_t mask)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + sizeof(mask) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    memcpy(m->value + EXP_ID_LEN + sizeof(value), &mask, sizeof(mask));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + sizeof(mask) + 4;
    return m;
}

struct ofl_match_tlv *
ofl_structs_match_exp_put64(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint64_t value)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + 4;
    return m;
}

struct ofl_match_tlv *
ofl_structs_match_exp_put64m(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint64_t value, uint64_t mask)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + sizeof(mask) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    memcpy(m->value + EXP_ID_LEN + sizeof(value), &mask, sizeof(mask));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + sizeof(mask) + 4;
    return m;
}

/*Functions used by experimenter errors*/

uint32_t
get_experimenter_id(struct ofl_msg_header const *msg)
{
    uint32_t exp_id;
    exp_id = BEBA_VENDOR_ID;
    /*check if the msg that triggers the err is experimenter*/
    if (msg->type == OFPT_EXPERIMENTER){
        exp_id = ((struct ofl_msg_experimenter *) msg)->experimenter_id;
    }
    /*if not, the error is triggered by an experimenter match/action*/
    else if(msg->type == OFPT_FLOW_MOD) {
        struct ofl_msg_flow_mod *flow_mod = (struct ofl_msg_flow_mod *)msg;
        struct ofl_match_header *flow_mod_match = flow_mod->match;
        exp_id = get_experimenter_id_from_match((struct ofl_match*)flow_mod_match);
        if(!exp_id){
            int i;
            for(i=0; i<flow_mod->instructions_num; i++){
                struct ofl_instruction_header *inst = flow_mod->instructions[i];
                switch(inst->type) {
                    case (OFPIT_WRITE_ACTIONS):
                    case (OFPIT_APPLY_ACTIONS): {
                        struct ofl_instruction_actions *act = (struct ofl_instruction_actions *)inst;
                        exp_id = get_experimenter_id_from_action(act);
                        break;
                    }
                    case (OFPIT_EXPERIMENTER): {
                        struct ofl_instruction_experimenter *exp_inst = (struct ofl_instruction_experimenter *) inst;
                        exp_id = exp_inst -> experimenter_id;
                        break;
                    }
                    case (OFPIT_CLEAR_ACTIONS):
                    case (OFPIT_GOTO_TABLE):
                    case (OFPIT_WRITE_METADATA):
                    case (OFPIT_METER):
            OFL_LOG_WARN(LOG_MODULE, "Get experimenter id: unexpected instruction!");
                }
            }
        }
    }
    return exp_id;
}

uint32_t
get_experimenter_id_from_match(struct ofl_match const *flow_mod_match)
{
    struct ofl_match_tlv *f;
    HMAP_FOR_EACH(f, struct ofl_match_tlv, hmap_node, &flow_mod_match->match_fields){
        switch (OXM_VENDOR(f->header))
        {
            case(OFPXMC_EXPERIMENTER):
                return *((uint32_t*) (f->value));
        }

    }
    return 0;
}

uint32_t
get_experimenter_id_from_action(struct ofl_instruction_actions const *act)
{
    int j;
    for(j=0; j<act->actions_num; j++) {
        struct ofl_action_header *action = act->actions[j];
        if (action->type == OFPAT_EXPERIMENTER) {
           return ((struct ofl_action_experimenter *)action)->experimenter_id;
        }
    }
    return 0;
}

/*Functions used by INsP experimenter instruction*/
struct pkttmp_table *
pkttmp_table_create(struct datapath *dp) {
    struct pkttmp_table *table;
    //size_t i;

    OFL_LOG_DBG(LOG_MODULE, "Creating PKTTMP TABLE.");

    table = xmalloc(sizeof(struct pkttmp_table));
    table->dp = dp;

    table->entries_num = 0;
    hmap_init(&table->entries);

    return table;
}

void
pkttmp_table_destroy(struct pkttmp_table *table) {
    struct pkttmp_entry *entry, *next;

    HMAP_FOR_EACH_SAFE(entry, next, struct pkttmp_entry, node, &table->entries) {
        pkttmp_entry_destroy(entry);
    }

    free(table);
}

struct pkttmp_entry *
pkttmp_entry_create(struct datapath *dp, struct pkttmp_table *table, struct ofl_exp_add_pkttmp *mod) {
    struct pkttmp_entry *e;
    //size_t i;
    uint64_t now_ms;
    now_ms = time_msec();

    e = xmalloc(sizeof(struct pkttmp_entry));
    e->created = now_ms;
    e->dp = dp;
    e->table = table;
    e->pkttmp_id = mod->pkttmp_id;
    e->data = NULL;
    e->data_length = mod->data_length;
    if (e->data_length > 0) {
        e->data = xmalloc(e->data_length);
        memcpy(e->data, mod->data, e->data_length);
    }
    //e->data = mod->data_length > 0 ? (uint8_t *)memcpy(malloc(mod->data_length), mod->data, mod->data_length) : NULL;


    OFL_LOG_DBG(LOG_MODULE, "Creating PKTTMP entry with following values id %u, data_len %zu.",e->pkttmp_id, e->data_length);

    return e;
}

void
pkttmp_entry_destroy(struct pkttmp_entry *entry) {
    free(entry->data);
    free(entry);
}

ofl_err state_table_set_header_field_extractor(struct state_table *table, struct ofl_exp_set_header_field_extractor *hfe) {
    struct key_extractor *dest;

    dest = &table->header_field_extractor[hfe->extractor_id];
    dest->field_count = 1;
    dest->fields[0] = hfe->field;
    dest->key_len = OXM_LENGTH(hfe->field);
    OFL_LOG_DBG(LOG_MODULE, "Header field extractor %u configured", hfe->extractor_id);

    return 0;
}
