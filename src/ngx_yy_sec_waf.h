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

int ngx_yy_sec_waf_unescape(ngx_str_t *str);

u_char *ngx_yy_sec_waf_itoa(ngx_pool_t *p, ngx_int_t n);
u_char *ngx_yy_sec_waf_uitoa(ngx_pool_t *p, ngx_uint_t n);

#define REQUEST_HEADER_PHASE    1
#define REQUEST_BODY_PHASE      2
#define RESPONSE_HEADER_PHASE   4
#define RESPONSE_BODY_PHASE     8

extern ngx_module_t ngx_http_yy_sec_waf_module;

extern ngx_atomic_t	  *request_matched;
extern ngx_atomic_t	  *request_blocked;
extern ngx_atomic_t	  *request_allowed;
extern ngx_atomic_t	  *request_logged;

typedef struct ngx_http_yy_sec_waf_rule {
    ngx_str_t *str; /* STR */
    ngx_http_regex_t *regex; /* REG */
    ngx_str_t *eq; /* EQ */
    ngx_str_t *gt;
    ngx_str_t *gids; /* GIDS */
    ngx_str_t *msg; /* MSG */
    ngx_int_t  rule_id;
    ngx_int_t  phase;

    /*target variable index array*/
    ngx_array_t  var_index;

    /* operators*/
    ngx_flag_t op_negative;

    void *op_metadata;
    void *action_metadata;
    void *tfn_metadata;

    /* actions*/
    ngx_flag_t     action_level;
    ngx_uint_t     status;
    ngx_flag_t     is_chain;
} ngx_http_yy_sec_waf_rule_t;

typedef struct {
    /* ngx_http_yy_sec_waf_rule_t */
    ngx_array_t *request_header_rules;
    ngx_array_t *request_body_rules;
    ngx_array_t *response_header_rules;
    ngx_array_t *response_body_rules;

    ngx_shm_zone_t *shm_zone;
    ngx_str_t *denied_url;
    ngx_flag_t enabled;
    ngx_flag_t conn_processor;
    ngx_flag_t body_processor;
} ngx_http_yy_sec_waf_loc_conf_t;

typedef struct {
    ngx_http_request_t *r;
    ngx_pool_t *pool;
    ngx_http_yy_sec_waf_loc_conf_t *cf;
    ngx_int_t  phase;

    ngx_rbtree_t cache_rbtree;
    ngx_rbtree_node_t cache_sentinel;

    ngx_str_t  args;

    ngx_str_t  post_args;
    ngx_uint_t post_args_count;

    ngx_str_t  *real_client_ip;
    ngx_str_t  server_ip;

    u_char     *boundary;
    ngx_uint_t  boundary_len;
    ngx_array_t multipart_filename;
    ngx_array_t multipart_name;
    ngx_array_t content_type;

    ngx_int_t  process_body_error;
    ngx_str_t  process_body_error_msg;
    ngx_uint_t post_args_len;
    ngx_uint_t conn_per_ip;
    ngx_int_t  var_index;
    ngx_str_t  var;

    /* level flags*/
    ngx_flag_t    action_level;
    ngx_uint_t    status;

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

ngx_int_t ngx_http_yy_sec_waf_process_conn(ngx_http_request_ctx_t *ctx);

ngx_shm_zone_t *ngx_http_yy_sec_waf_create_shm_zone(ngx_conf_t *cf);

ngx_int_t ngx_http_yy_sec_waf_process_body(ngx_http_request_t *r,
    ngx_http_yy_sec_waf_loc_conf_t *cf, ngx_http_request_ctx_t *ctx);


#endif

