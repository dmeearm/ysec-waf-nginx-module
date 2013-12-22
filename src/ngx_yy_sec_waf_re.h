#ifndef __YY_SEC_WAF_RE_H__
#define __YY_SEC_WAF_RE_H__

/*
** @file: ngx_yy_sec_waf_re.h
** @description: This is header file for the rule engine of yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.11.14
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"


#define STR   "str:"
#define REGEX "regex:"
#define EQ    "eq:"
#define GT    "gt:"
#define GIDS  "gids:"
#define ID    "id:"
#define MSG   "msg:"
#define POS   "pos:"
#define LEVEL "lev:"
#define PHASE "phase:"

#define TFNS "t:"

/* LEV */
#define LOG   "log"
#define BLOCK "block"
#define ALLOW "allow"

#define ACTION_NONE    0
#define ACTION_LOG     1
#define ACTION_BLOCK   2
#define ACTION_ALLOW   4

#define RULE_MATCH              1
#define RULE_NO_MATCH           2

#define UNCOMMON_CONTENT_TYPE     10
#define UNCOMMON_FILENAME         11
#define UNCOMMON_FILENAME_POSTFIX 12
#define UNCOMMON_HEX_ENCODING     13
#define UNCOMMON_POST_BOUNDARY    14
#define UNCOMMON_POST_FORMAT      15

#define NEXT_CHAIN                 1
#define NEXT_RULE                  2

typedef void* (*fn_op_parse_t)(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
typedef ngx_int_t (*fn_op_execute_t)(ngx_http_request_t *r,
    ngx_str_t *str, ngx_http_yy_sec_waf_rule_t *rule);

typedef struct {
    const ngx_str_t name;
    fn_op_parse_t parse;
    fn_op_execute_t execute;
} re_op_metadata;

typedef ngx_int_t (*fn_tfns_execute_t)(ngx_http_variable_value_t *v);

typedef struct {
    const ngx_str_t name;
    fn_tfns_execute_t execute;
} re_tfns_metadata;

typedef void* (*fn_action_parse_t)(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);

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

ngx_int_t ngx_http_yy_sec_waf_add_variables(ngx_conf_t *cf);

ngx_int_t ngx_http_yy_sec_waf_init_variables_in_hash(ngx_conf_t *cf,
    ngx_hash_t *hash);

ngx_int_t ngx_http_yy_sec_waf_init_operators_in_hash(ngx_conf_t *cf,
    ngx_hash_t *hash);

ngx_int_t ngx_http_yy_sec_waf_init_actions_in_hash(ngx_conf_t *cf,
    ngx_hash_t *hash);

ngx_int_t ngx_http_yy_sec_waf_init_tfns_in_hash(ngx_conf_t *cf,
    ngx_hash_t *hash);

re_tfns_metadata *yy_sec_waf_re_resolve_tfn_in_hash(ngx_str_t *tfn);

ngx_inline void yy_sec_waf_re_cache_init_rbtree(ngx_rbtree_t *rbtree,
    ngx_rbtree_node_t *sentinel);

ngx_int_t yy_sec_waf_re_cache_set_value(ngx_pool_t *pool,
    ngx_str_t *name, ngx_array_t *value, ngx_rbtree_t *rbtree);

ngx_inline ngx_str_t *yy_sec_waf_re_cache_get_value(ngx_rbtree_t *rbtree,
    ngx_str_t *name);

#endif

