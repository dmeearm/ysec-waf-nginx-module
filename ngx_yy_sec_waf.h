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
#define GIDS "gids:"
#define MSG "msg:"
#define POS "pos:"

#define HEADER "HEADER"
#define BODY "BODY"
#define URL "URL"
#define ARGS "ARGS"
#define COOKIE "COOKIE"

extern ngx_module_t  ngx_http_yy_sec_waf_module;

int ngx_yy_sec_waf_unescape(ngx_str_t *str);

typedef struct {
    ngx_str_t *str;
    ngx_regex_compile_t *rgc;
    ngx_str_t *gids;
    ngx_str_t *msg;

    ngx_flag_t body:1;
    ngx_flag_t header:1;
    ngx_flag_t url:1;
    ngx_flag_t args:1;
    ngx_flag_t cookie:1;
} ngx_http_yy_sec_waf_rule_t;

typedef struct {
    ngx_array_t *header_rules;/* ngx_http_yy_sec_waf_rule_t */
    ngx_array_t *args_rules; 
} ngx_http_yy_sec_waf_loc_conf_t;

typedef struct {
    ngx_flag_t    ready:1;
    ngx_flag_t    matched:1;
    ngx_flag_t    wait_for_body:1;
} ngx_http_request_ctx_t;


#endif

