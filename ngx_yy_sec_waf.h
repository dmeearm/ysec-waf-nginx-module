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

#include "ngx_yy_sec_waf_re.h"

int ngx_yy_sec_waf_unescape(ngx_str_t *str);

ngx_int_t ngx_http_yy_sec_waf_execute_null(ngx_http_request_t *r,
    ngx_str_t *str, void *rule);



extern ngx_module_t  ngx_http_yy_sec_waf_module;

typedef struct ngx_http_yy_sec_waf_rule {
    ngx_str_t *str; /* STR */
    ngx_http_regex_t *regex; /* REG */
    ngx_str_t *eq; /* EQ */
    ngx_str_t *gids; /* GIDS */
    ngx_str_t *msg; /* MSG */
    ngx_int_t  rule_id;
    ngx_int_t  phase;
    ngx_int_t  var_index;

    ngx_str_t op_name;

    re_var_metadata *var_metadata;
    re_op_metadata *op_metadata;
    re_tfs_metadata *tfs_metadata;

    /* LEVEL*/
    ngx_flag_t    log:1;
    ngx_flag_t    block:1;
    ngx_flag_t    allow:1;
} ngx_http_yy_sec_waf_rule_t;

typedef struct {
    /* ngx_http_yy_sec_waf_rule_t */
    ngx_array_t *request_header_rules;
    ngx_array_t *request_body_rules;

    ngx_hash_t *variables_in_hash;
    ngx_hash_t *operators_in_hash;

    ngx_str_t *denied_url;
    ngx_uint_t http_method;
    ngx_uint_t max_post_args_len;
    ngx_flag_t enabled;

    /* count */
    ngx_uint_t    request_processed;
    ngx_uint_t    request_matched;
    ngx_uint_t    request_blocked;
    ngx_uint_t    request_allowed;
} ngx_http_yy_sec_waf_loc_conf_t;

typedef struct {
    ngx_http_request_t *r;
    ngx_http_yy_sec_waf_loc_conf_t *cf;
    ngx_int_t  phase;

    ngx_str_t *args;

    ngx_str_t *post_args;

    u_char *boundary;
    ngx_uint_t boundary_len;
    ngx_array_t *multipart_filename;
    ngx_array_t *multipart_name;
    ngx_array_t *content_type;

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

