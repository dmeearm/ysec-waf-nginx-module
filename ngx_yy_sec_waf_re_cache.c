/*
** @file: ngx_yy_sec_waf_re_cache.c
** @description: This is the rule engine's cache for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.12.03
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

typedef struct {
    ngx_str_node_t node;
    ngx_str_t value;
} re_cache_node_t;

