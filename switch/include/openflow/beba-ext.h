#ifndef BEBA_EXT_H
#define BEBA_EXT_H 1

#include "openflow/openflow.h"

/*
 * The following are vendor extensions from OpenFlow.  This is a
 * means of allowing the introduction of non-standardized
 * proposed code.
 *
 * Structures in this file are 64-bit aligned in size.
 */

#define BEBA_VENDOR_ID 0xBEBABEBA
#define OFP_GLOBAL_STATE_DEFAULT 0

enum oxm_exp_match_fields {
    OFPXMT_EXP_GLOBAL_STATE,      /* Global state */
    OFPXMT_EXP_STATE,             /* Flow State */
    OFPXMT_EXP_CONDITION0,        /* Condition 0 */
    OFPXMT_EXP_CONDITION1,        /* Condition 1 */
    OFPXMT_EXP_CONDITION2,        /* Condition 2 */
    OFPXMT_EXP_CONDITION3,        /* Condition 3 */
    OFPXMT_EXP_CONDITION4,        /* Condition 4 */
    OFPXMT_EXP_CONDITION5,        /* Condition 5 */
    OFPXMT_EXP_CONDITION6,        /* Condition 6 */
    OFPXMT_EXP_CONDITION7,        /* Condition 7 */
    OFPXMT_EXP_TIMESTAMP,         /* Timestamp */
    OFPXMT_EXP_RANDOM,            /* Random */
    OFPXMT_EXP_PKT_LEN            /* Packet length */
};

/****************************************************************
 *
 * OpenFlow experimenter Instructions
 *
 ****************************************************************/
enum ofp_exp_instructions {
    OFPIT_IN_SWITCH_PKT_GEN
};

struct ofp_beba_instruction_experimenter_header {
    struct ofp_instruction_experimenter_header header;   /*  OpenFlow's standard experimenter action header*/
    uint32_t instr_type;   /* type in header is OFPIT_EXPERIMENTER, instr_type is one of ofp_exp_instructions */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_beba_instruction_experimenter_header) == 16);

struct ofp_exp_instruction_in_switch_pkt_gen {
	struct ofp_beba_instruction_experimenter_header header; /* OpenFlow standard experimenter instruction header */
	uint32_t pkttmp_id;
	uint8_t pad[4];
	struct ofp_action_header actions[0]; /* Same actions that can be associated with OFPIT_APPLY_ACTIONS */
};
OFP_ASSERT(sizeof(struct ofp_exp_instruction_in_switch_pkt_gen) == 24);

/****************************************************************
 *
 * OpenFlow experimenter Actions
 *
 ****************************************************************/
enum ofp_exp_actions {
    OFPAT_EXP_SET_STATE,
    OFPAT_EXP_SET_GLOBAL_STATE,
    OFPAT_EXP_INC_STATE,
    OFPAT_EXP_SET_DATA_VAR,
    OFPAT_EXP_WRITE_CONTEXT_TO_FIELD,
    OFPAT_EXP_DECAPSULATE_GTP,
    OFPAT_EXP_ENCAPSULATE_GTP,
    OFPAT_EXP_SOFT_DECAPSULATE_GTP
};

struct ofp_beba_action_experimenter_header {
    struct ofp_action_experimenter_header header;   /*  OpenFlow's standard experimenter action header*/
    uint32_t act_type;   /* type in header is OFPAT_EXPERIMENTER, act_type is one of ofp_exp_actions */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_beba_action_experimenter_header) == 16);

/* Action structure for OFPAT_EXP_SET_STATE */
struct ofp_exp_action_set_state {
    struct ofp_beba_action_experimenter_header header;
    uint32_t state; /* State instance. */
    uint32_t state_mask; /* State mask */
    uint8_t table_id; /*Stage destination*/
    uint8_t pad[3];
    uint32_t hard_rollback;
    uint32_t idle_rollback;
    uint32_t hard_timeout;
    uint32_t idle_timeout;
    uint8_t bit; /* Swapping bit */
    uint8_t pad2[7];   /* Align to 64-bits. */
    uint32_t field_count;
    uint32_t fields[0]; // variable number of fields (sizeof() ignores flexible arrays)
};
OFP_ASSERT(sizeof(struct ofp_exp_action_set_state) == 56);


/* Action structure for OFPAT_EXP_SET_GLOBAL_STATE */
struct ofp_exp_action_set_global_state {
    struct ofp_beba_action_experimenter_header header;
    uint32_t global_state;
    uint32_t global_state_mask;
};
OFP_ASSERT(sizeof(struct ofp_exp_action_set_global_state) == 24);


/* Action structure for OFPAT_EXP_INC_STATE */
struct ofp_exp_action_inc_state {
    struct ofp_beba_action_experimenter_header header;
    uint8_t table_id;
    uint8_t pad[7]; 
};
OFP_ASSERT(sizeof(struct ofp_exp_action_inc_state) == 24);

/*
//TODO Davide: refactoring of "ofp_exp_action_set_data_variable" and "ofp_exp_set_condition"
"operand_types" field can be removed and operand_X can be assigned a value
0 <= value <= OFPSC_MAX_FLOW_DATA_VAR_NUM-1 for flow data variable ids
OFPSC_MAX_FLOW_DATA_VAR_NUM <= value <= OFPSC_MAX_FLOW_DATA_VAR_NUM + OFPSC_MAX_GLOBAL_DATA_VAR_NUM -1 for global data var ids
OFPSC_MAX_FLOW_DATA_VAR_NUM + OFPSC_MAX_GLOBAL_DATA_VAR_NUM <= value <= OFPSC_MAX_FLOW_DATA_VAR_NUM + OFPSC_MAX_GLOBAL_DATA_VAR_NUM + OFPSC_MAX_HEADER_FIELDS -1 for header field extractors
NB: the CTRL should hide this detail!
*/

/* Action structure for OFPAT_EXP_SET_DATA_VAR */
struct ofp_exp_action_set_data_variable {
    struct ofp_beba_action_experimenter_header header;
    uint16_t operand_types;
    uint8_t table_id;
    uint8_t opcode;
    uint8_t output;
    uint8_t pad2[3];   /* Align to 64-bits. */
    uint8_t operand_1;
    uint8_t operand_2;
    uint8_t operand_3;
    uint8_t operand_4;
    int8_t coeff_1;
    int8_t coeff_2;
    int8_t coeff_3;
    int8_t coeff_4;
    uint32_t field_count;
    uint8_t bit;
    uint8_t pad3[3];
    uint32_t fields[0]; // variable number of fields (sizeof() ignores flexible arrays)
};
OFP_ASSERT(sizeof(struct ofp_exp_action_set_data_variable) == 40);

/* Action structure for OFPAT_EXP_WRITE_CONTEXT_TO_FIELD */
struct ofp_exp_action_write_context_to_field {
    struct ofp_beba_action_experimenter_header header;
    uint8_t src_type;
    uint8_t src_id;
    uint8_t pad2[2];
    uint32_t dst_field;   /* Align to 64-bits. */
};
OFP_ASSERT(sizeof(struct ofp_exp_action_write_context_to_field) == 24);

/* Action structure for OFPAT_EXP_ENCAPSULATE_GTP */
struct ofp_exp_action_encapsulate_gtp {
    struct ofp_beba_action_experimenter_header header;
    uint32_t pkttmp_id;
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_exp_action_encapsulate_gtp) == 24);

/* Action structure for OFPAT_EXP_DECAPSULATE */
struct ofp_exp_action_decapsulate_gtp {
    struct ofp_beba_action_experimenter_header header;  /* we only need the action id */
};
OFP_ASSERT(sizeof(struct ofp_exp_action_decapsulate_gtp) == 16);

/* Action structure for OFPAT_EXP_SOFT_DECAPSULATE */
struct ofp_exp_action_soft_decapsulate_gtp {
    struct ofp_beba_action_experimenter_header header;  /* we only need the action id */
};
OFP_ASSERT(sizeof(struct ofp_exp_action_soft_decapsulate_gtp) == 16);


/*EXPERIMENTER MESSAGES*/
/*
 * State Sync:
 * |--> OFPT_EXP_STATE_CHANGED notifies the controller about a state transition;
 * |--> OFPT_EXP_FLOW_NOTIFICATION notifies the controller about an (actually) installed flow modification in the flow table.
 */
enum ofp_exp_messages {
    OFPT_EXP_STATE_MOD,
    OFPT_EXP_PKTTMP_MOD,
    OFPT_EXP_STATE_CHANGED,
    OFPT_EXP_FLOW_NOTIFICATION
    // Missing type: Notification for missing packet template (after NEC people provide their code)
};

/*EXPERIMENTER ERROR MESSAGES*/
enum ofp_exp_beba_errors{
    OFPEC_EXP_STATE_MOD_FAILED,
    OFPEC_EXP_STATE_MOD_BAD_COMMAND,
    OFPEC_EXP_SET_EXTRACTOR,
    OFPEC_EXP_SET_FLOW_STATE,
    OFPEC_EXP_DEL_FLOW_STATE,
    OFPEC_BAD_EXP_MESSAGE,
    OFPEC_BAD_EXP_ACTION,
    OFPEC_BAD_EXP_LEN,
    OFPEC_BAD_TABLE_ID,
    OFPEC_BAD_MATCH_WILDCARD,
    OFPET_BAD_EXP_INSTRUCTION,
    OFPEC_EXP_PKTTMP_MOD_FAILED,
    OFPEC_EXP_PKTTMP_MOD_BAD_COMMAND,
    OFPEC_BAD_EXTRACTOR_ID,
    OFPEC_BAD_CONDITION_ID,
    OFPEC_BAD_CONDITION,
    OFPEC_BAD_OPERAND_TYPE,
    OFPEC_BAD_FLOW_DATA_VAR_ID,
    OFPEC_BAD_GLOBAL_DATA_VAR_ID,
    OFPEC_BAD_HEADER_FIELD_SIZE,
    OFPEC_BAD_OPCODE,
    OFPEC_BAD_HEADER_EXTRACTOR,
    OFPEC_BAD_SOURCE_TYPE
};

/****************************************************************
 *
 *   OFPT_EXP_STATE_MOD
 *
****************************************************************/
#define OFPSC_MAX_FIELD_COUNT 6
#define OFPSC_MAX_KEY_LEN 48
#define OFPSC_MAX_HEADER_FIELDS 8
#define OFPSC_MAX_CONDITIONS_NUM 8
#define OFPSC_MAX_FLOW_DATA_VAR_NUM 8
#define OFPSC_MAX_GLOBAL_DATA_VAR_NUM 8
#define MULTIPLY_FACTOR 1000 // used for OPCODE_AVG, OPCODE_VAR and OPCODE_EWMA

struct ofp_exp_msg_state_mod {
    struct ofp_experimenter_header header; /* OpenFlow's standard experimenter message header */
    uint8_t command;
    uint8_t pad;
    uint8_t payload[];
};

/*
 * State Sync: Message format of a state notification
 * When a state transition occurs in the state table, controller gets notified.
 */
struct ofp_exp_msg_state_ntf {
    struct   ofp_experimenter_header header; // OpenFlow's standard experimenter
    uint32_t table_id;
    uint32_t old_state;
    uint32_t new_state;
    uint32_t state_mask;
    uint32_t key_len;
    uint8_t  key[OFPSC_MAX_KEY_LEN];  //TODO Davide: use flexible arrays to save space
    uint32_t flow_data_var[OFPSC_MAX_FLOW_DATA_VAR_NUM];
};

/*
 * State Sync: Message format of a positive flow modification acknowledgment
 * (i.e., when a flow is really installed in the flow table, switch notifies the controller)
 * Useful for bulk updates
 */
struct ofp_exp_msg_flow_ntf {
    struct   ofp_experimenter_header header;
    uint32_t table_id;
    uint32_t ntf_type;
    struct   ofp_match match;
};

struct ofp_exp_stateful_table_config {
    uint8_t table_id;
    uint8_t stateful;
};

struct ofp_exp_set_extractor {
    uint8_t table_id;
    uint8_t biflow;
    uint8_t pad[2];
    uint8_t bit;
    uint8_t pad2[3];
    uint32_t field_count;
    uint32_t fields[OFPSC_MAX_FIELD_COUNT];  //TODO Davide: use flexible arrays to save space
};

struct ofp_exp_set_flow_state {
    uint8_t table_id;
    uint8_t pad[3];
    uint32_t key_len;
    uint32_t state;
    uint32_t state_mask;
    uint32_t hard_rollback;
    uint32_t idle_rollback;
    uint32_t hard_timeout;
    uint32_t idle_timeout;
    uint8_t key[OFPSC_MAX_KEY_LEN];  //TODO Davide: use flexible arrays to save space
};

struct ofp_exp_del_flow_state {
    uint8_t table_id;
    uint8_t pad[3];
    uint32_t key_len;
    uint8_t key[OFPSC_MAX_KEY_LEN];  //TODO Davide: use flexible arrays to save space
};

struct ofp_exp_set_global_state {
    uint32_t global_state;
    uint32_t global_state_mask;
};

struct ofp_exp_set_header_field_extractor {
    uint8_t table_id;
    uint8_t extractor_id;
    uint8_t pad[2];
    uint32_t field;
};

struct ofp_exp_set_condition {
    uint8_t table_id;
    uint8_t condition_id;
    uint8_t condition;
    uint8_t operand_types;
    uint8_t operand_1;
    uint8_t operand_2;
    uint8_t pad[2];
};

struct ofp_exp_set_global_data_variable {
    uint8_t table_id;
    uint8_t global_data_variable_id;
    uint8_t pad[2];
    uint32_t value;
    uint32_t mask;
};

struct ofp_exp_set_flow_data_variable {
    uint8_t table_id;
    uint8_t flow_data_variable_id;
    uint8_t pad[2];
    uint32_t key_len;
    uint32_t value;
    uint32_t mask;
    uint8_t key[OFPSC_MAX_KEY_LEN];  //TODO Davide: use flexible arrays to save space
};

enum ofp_exp_operand_types {
    OPERAND_TYPE_FLOW_DATA_VAR = 0,
    OPERAND_TYPE_GLOBAL_DATA_VAR,
    OPERAND_TYPE_HEADER_FIELD,
    OPERAND_TYPE_CONSTANT
};

enum ofp_exp_conditions {
    CONDITION_GT = 0,
    CONDITION_LT,
    CONDITION_GTE,
    CONDITION_LTE,
    CONDITION_EQ,
    CONDITION_NEQ
};

enum ofp_exp_opcode {
    OPCODE_SUM = 0,
    OPCODE_SUB,
    OPCODE_MUL,
    OPCODE_DIV,
    OPCODE_AVG,
    OPCODE_VAR,
    OPCODE_EWMA,
    OPCODE_POLY_SUM
};

enum ofp_exp_ewma_params {
    EWMA_PARAM_0125 = 0, 
    EWMA_PARAM_0250,
    EWMA_PARAM_0375,
    EWMA_PARAM_0500,
    EWMA_PARAM_0625,
    EWMA_PARAM_0750,
    EWMA_PARAM_0875
};

enum ofp_exp_source_types {
    SOURCE_TYPE_FLOW_DATA_VAR = 0,
    SOURCE_TYPE_GLOBAL_DATA_VAR,
    SOURCE_TYPE_STATE
};

enum ofp_exp_msg_state_mod_commands {
    OFPSC_STATEFUL_TABLE_CONFIG = 0,
    OFPSC_EXP_SET_L_EXTRACTOR,
    OFPSC_EXP_SET_U_EXTRACTOR,
    OFPSC_EXP_SET_FLOW_STATE,   
    OFPSC_EXP_DEL_FLOW_STATE,
    OFPSC_EXP_SET_GLOBAL_STATE,
    OFPSC_EXP_RESET_GLOBAL_STATE,
    OFPSC_EXP_SET_HEADER_FIELD_EXTRACTOR,
    OFPSC_EXP_SET_CONDITION,
    OFPSC_EXP_SET_GLOBAL_DATA_VAR,
    OFPSC_EXP_SET_FLOW_DATA_VAR
};

/****************************************************************
 *
 *   OFPT_EXP_PKTTMP_MOD
 *
****************************************************************/

struct ofp_exp_msg_pkttmp_mod {
    struct ofp_experimenter_header header; /* OpenFlow's standard experimenter message header */
    uint8_t command;
    uint8_t pad;
    uint8_t payload[];
};

struct ofp_exp_add_pkttmp {
	uint32_t pkttmp_id;
	uint8_t pad[4];
	/* uint8_t data[0]; */ /* Packet data. The length is inferred
			from the length field in the header. */
};

struct ofp_exp_del_pkttmp {
	uint32_t pkttmp_id;
	uint8_t pad[4];
};

enum ofp_exp_msg_pkttmp_mod_commands {
    OFPSC_ADD_PKTTMP = 0,
    OFPSC_DEL_PKTTMP
};

/****************************************************************
 *
 *   MULTIPART MESSAGE: OFPMP_EXP_STATE_STATS
 *
****************************************************************/
enum ofp_stats_extension_commands {
    OFPMP_EXP_STATE_STATS,      
    OFPMP_EXP_GLOBAL_STATE_STATS,
    OFPMP_EXP_STATE_STATS_AND_DELETE
};

struct ofp_exp_state_entry{
    uint32_t            key_len;
    uint8_t             key[OFPSC_MAX_KEY_LEN];
    uint32_t            state;
    uint32_t            flow_data_var[OFPSC_MAX_FLOW_DATA_VAR_NUM]; //TODO Davide: use flexible arrays to save space
};
OFP_ASSERT(sizeof(struct ofp_exp_state_entry) == 88);

/* Body for ofp_multipart_request of type OFPMP_EXP_STATE_STATS. */
struct ofp_exp_state_stats_request {
    struct ofp_experimenter_stats_header header;
    uint8_t                 table_id;       /* ID of table to read (from ofp_table_stats),
                               OFPTT_ALL for all tables. */
    uint8_t                 get_from_state;
    uint8_t                 pad[2];         /* Align to 64 bits. */
    uint32_t                state;   
    struct ofp_match        match; /* Fields to match. Variable size. */
};
OFP_ASSERT(sizeof(struct ofp_exp_state_stats_request) == 24);

/* Body of reply to OFPMP_EXP_STATE_STATS request. */
struct ofp_exp_state_stats_reply{
    struct ofp_experimenter_stats_header header;
    struct ofp_exp_state_stats *stats;
};

struct ofp_exp_state_stats {
    uint16_t length;        /* Length of this entry. */
    uint8_t table_id;       /* ID of table flow came from. */
    uint8_t pad;
    uint32_t duration_sec;  /* Time state entry has been alive in secs. */
    uint32_t duration_nsec; /* Time state entry has been alive in nsecs beyond duration_sec. */
    uint32_t field_count;    /*number of extractor fields*/
    uint32_t fields[OFPSC_MAX_FIELD_COUNT]; /*extractor fields*/  //TODO Davide: use flexible arrays to save space
    struct ofp_exp_state_entry entry;
    uint32_t hard_rollback;
    uint32_t idle_rollback;
    uint32_t hard_timeout; // [us]
    uint32_t idle_timeout; // [us]
};
OFP_ASSERT(sizeof(struct ofp_exp_state_stats) == 144);

/****************************************************************
 *
 *   MULTIPART MESSAGE: OFPMP_EXP_GLOBAL_STATE_STATS
 *
****************************************************************/

/* Body for ofp_multipart_request of type OFPMP_EXP_GLOBAL_STATE_STATS. */
struct ofp_exp_global_state_stats_request {
    struct ofp_experimenter_stats_header header;
};
OFP_ASSERT(sizeof(struct ofp_exp_global_state_stats_request) == 8);

/* Body of reply to OFPMP_EXP_GLOBAL_STATE_STATS request. */
struct ofp_exp_global_state_stats {
    struct ofp_experimenter_stats_header header;
    uint8_t pad[4];
    uint32_t global_state;
};
OFP_ASSERT(sizeof(struct ofp_exp_global_state_stats) == 16);

#endif /* BEBA_EXT_H */
