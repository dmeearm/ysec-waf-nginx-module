#ifndef __YY_SEC_WAF_RE_H__
#define __YY_SEC_WAF_RE_H__

/*
** @file: ngx_yy_sec_waf_re.h
** @description: This is header file for the rule rule engine of yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.11.14
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"


#define STR "str:"
#define REGEX "regex:"
#define EQ "eq:"
#define GT "gt:"
#define GIDS "gids:"
#define ID "id:"
#define MSG "msg:"
#define POS "pos:"
#define LEVEL "lev:"
#define PHASE "phase:"

#define TFNS "t:"

/* LEV */
#define LOG "log"
#define BLOCK "block"
#define ALLOW "allow"

#define RULE_MATCH              1
#define RULE_NO_MATCH           2

#define REQUEST_HEADER_PHASE 0x01
#define REQUEST_BODY_PHASE 0x10

#define UNCOMMON_CONTENT_TYPE 10
#define UNCOMMON_FILENAME 11
#define UNCOMMON_FILENAME_POSTFIX 12
#define UNCOMMON_HEX_ENCODING 13
#define UNCOMMON_POST_BOUNDARY 14
#define UNCOMMON_POST_FORMAT 15

typedef void* (*fn_op_parse_t)(ngx_conf_t *cf,
    ngx_str_t *tmp, void *rule);
typedef ngx_int_t (*fn_op_execute_t)(ngx_http_request_t *r,
    ngx_str_t *str, void *rule);

typedef struct {
    const ngx_str_t name;
    fn_op_parse_t parse;
    fn_op_execute_t execute;
} re_op_metadata;

typedef int (*fn_var_generate_t)(void *rule,
    void *ctx, ngx_array_t *var);

typedef struct {
    const ngx_str_t name;
    fn_var_generate_t generate;
} re_var_metadata;

typedef ngx_int_t (*fn_tfns_execute_t)(ngx_str_t *str);

typedef struct {
    const ngx_str_t name;
    fn_tfns_execute_t execute;
} re_tfns_metadata;

typedef void* (*fn_action_parse_t)(ngx_conf_t *cf,
    ngx_str_t *tmp, void *rule);

typedef struct {
    const ngx_str_t name;
    fn_action_parse_t parse;
} re_action_metadata;

typedef struct {
    ngx_hash_t variables_in_hash;
    ngx_hash_t operators_in_hash;
    ngx_hash_t actions_in_hash;
    ngx_hash_t tfns_in_hash;
} yy_sec_waf_re_t;

re_action_metadata *yy_sec_waf_re_resolve_action_in_hash(ngx_str_t *action);

re_op_metadata *yy_sec_waf_re_resolve_operator_in_hash(ngx_str_t *operator);

re_tfns_metadata *yy_sec_waf_re_resolve_tfn_in_hash(ngx_str_t *tfn);

re_var_metadata *yy_sec_waf_re_resolve_variable_in_hash(ngx_str_t *variable);


#endif

