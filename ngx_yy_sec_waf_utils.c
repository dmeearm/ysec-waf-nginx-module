/*
** @file: ngx_yy_sec_waf_utils.c
** @description: This is the utils defined for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.10
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

/* 
** @description: Unescape routine.
** @para: ngx_str_t *str
** @return: uint (nullbytes+bad)
*/

int
ngx_yy_sec_waf_unescape(ngx_str_t *str) {
    u_char *dst, *src;
    u_int nullbytes = 0, i;
    
    dst = str->data;
    src = str->data;
        
    ngx_unescape_uri(&src, &dst, str->len, 0);

    str->len = src - str->data;

    /* tmp hack fix, avoid %00 & co (null byte) encoding :p */
    for (i = 0; i < str->len; i++) {
        if (str->data[i] == 0x0) {
    	    nullbytes++;
    	    //str->data[i] = '0';
        }
    }

    return nullbytes;
}

