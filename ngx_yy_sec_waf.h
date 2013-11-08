#ifndef __YY_SEC_WAF_H__
#define __YY_SEC_WAF_H__

/*
** @file: ngx_yy_sec_waf.h
** @description: This is the header file for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.10
** Copyright (C) YY, Inc.
*/

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>
#include <ngx_string.h>

#define STR "str:"
#define REGEX "regex:"
#define EQ "eq:"
#define MOD "mod:"
#define GIDS "gids:"
#define ID "id:"
#define MSG "msg:"
#define POS "pos:"
#define LEVEL "lev:"
#define PHASE "phase:"

/* POS */
#define HEADER "HEADER"
#define BODY "BODY"
#define URI "URI"
#define ARGS "ARGS"
#define COOKIE "COOKIE"

/* LEV */
#define LOG "LOG"
#define BLOCK "BLOCK"
#define ALLOW "ALLOW"

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

int ngx_yy_sec_waf_unescape(ngx_str_t *str);

ngx_int_t ngx_http_yy_sec_waf_execute_null(ngx_http_request_t *r,
    ngx_str_t *str, void *rule);


typedef void* (*fn_op_parse_t)(ngx_conf_t *cf,
    ngx_str_t *tmp, void *rule);
typedef ngx_int_t (*fn_op_execute_t)(ngx_http_request_t *r,
    ngx_str_t *str, void *rule);

typedef struct {
    const char *name;
    fn_op_parse_t parse;
    fn_op_execute_t execute;
} re_op_metadata;

typedef int (*fn_var_generate_t)(void *rule,
    void *ctx, ngx_str_t *var);

typedef struct {
    const char *name;
    fn_var_generate_t generate;
} re_var_metadata;

extern ngx_module_t  ngx_http_yy_sec_waf_module;
extern re_var_metadata var_metadata[];
extern re_op_metadata op_metadata[];

typedef struct ngx_http_yy_sec_waf_rule {
    ngx_str_t *str; /* STR */
    ngx_http_regex_t *regex; /* REG */
    ngx_str_t *eq; /* EQ */
    ngx_flag_t mod:1; /* MOD */
    ngx_str_t *gids; /* GIDS */
    ngx_str_t *msg; /* MSG */
    ngx_int_t  rule_id;
    ngx_int_t  phase;
    ngx_int_t  var_index;

    re_var_metadata *var_metadata;
    re_op_metadata *op_metadata;

    /* POS */
    ngx_flag_t body:1;
    ngx_flag_t header:1;
    ngx_flag_t uri:1;
    ngx_flag_t args:1;
    ngx_flag_t cookie:1;
    ngx_flag_t variable:1;
    /* LEVEL*/
    ngx_flag_t    log:1;
    ngx_flag_t    block:1;
    ngx_flag_t    allow:1;
} ngx_http_yy_sec_waf_rule_t;

typedef struct {
    /* ngx_http_yy_sec_waf_rule_t */
    ngx_array_t *request_header_rules;
    ngx_array_t *request_body_rules;

    ngx_str_t *denied_url;
    ngx_uint_t http_method;
    ngx_uint_t max_post_args_len;
    ngx_flag_t enabled;

    /* count */
    ngx_uint_t    request_processed;
    ngx_uint_t    request_matched;
    ngx_uint_t    request_blocked;
} ngx_http_yy_sec_waf_loc_conf_t;

typedef struct {
    ngx_http_request_t *r;
    ngx_http_yy_sec_waf_loc_conf_t *cf;
    ngx_int_t  phase;

    ngx_uint_t method;
    ngx_uint_t http_version;
    ngx_str_t request_line;
    ngx_str_t uri;
    ngx_str_t args;
    ngx_str_t exten;
    ngx_str_t unparsed_uri;
    ngx_str_t method_name;
    ngx_str_t http_protocol;
    ngx_http_headers_in_t *headers_in;

    ngx_str_t *post_args_value;

    u_char *boundary;
    ngx_uint_t boundary_len;
    ngx_str_t  multipart_filename;
    ngx_str_t  multipart_name;
    ngx_str_t  content_type;

    ngx_int_t  process_body_error;
    ngx_str_t *process_body_error_msg;
    ngx_uint_t post_args_len;

    ngx_int_t  var_index;

    /* blocking flags*/
    ngx_flag_t    log:1;
    ngx_flag_t    block:1;
    ngx_flag_t    allow:1;
    /* state */
    ngx_flag_t    process_done:1;
    ngx_flag_t    read_body_done:1;
    ngx_flag_t    waiting_more_body:1;

    ngx_flag_t    matched:1;
    ngx_int_t     rule_id;
    ngx_str_t    *gids;
    ngx_str_t    *msg;
    ngx_str_t    *matched_string;
} ngx_http_request_ctx_t;


ngx_int_t yy_sec_waf_re_process_normal_rules(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx);

ngx_int_t ngx_http_yy_sec_waf_process_basic_rules(ngx_http_request_t *r,
    ngx_str_t *str, ngx_array_t *rules, ngx_http_request_ctx_t *ctx);

#endif

