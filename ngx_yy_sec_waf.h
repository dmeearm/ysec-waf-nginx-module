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

typedef struct {
    ngx_str_t *str;
    ngx_regex_compile_t *rgc;
} ngx_http_yy_sec_waf_rule_t;

typedef struct {
    ngx_str_t    basic_rule;
    ngx_http_yy_sec_waf_rule_t *rule;
} ngx_http_yy_sec_waf_loc_conf_t;

typedef struct {
    ngx_flag_t    ready:1;
    ngx_flag_t    matched:1;
    ngx_flag_t    wait_for_body:1;
} ngx_http_request_ctx_t;


#endif

