/*
** @file: ngx_yy_sec_waf_utils.c
** @description: This is the utils defined for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.10
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

/*
** @description: Get from naxsi src.
** - Patched ngx_unescape_uri : 
** - The original one does not care if the character following % is in valid range.
** - For example, with the original one :
** - '%uff' -> 'uff'
** @para: u_char **dst
** @para: u_char **src
** @para: size_t size
** @para: ngx_uint_t type
** @return: int bad
*/

static int
ngx_yy_sec_waf_unescape_uri(u_char **dst, u_char **src, size_t size, ngx_uint_t type)
{
    u_char  *d, *s, ch, c, decoded;
    int bad = 0;
    
    enum {
        sw_usual = 0,
        sw_quoted,
        sw_quoted_second
    } state;

    d = *dst;
    s = *src;

    state = 0;
    decoded = 0;

    while (size--) {

        ch = *s++;

        switch (state) {
        case sw_usual:
            if (ch == '?'
                && (type & (NGX_UNESCAPE_URI|NGX_UNESCAPE_REDIRECT)))
            {
                *d++ = ch;
                goto done;
            }

            if (ch == '%') {
                state = sw_quoted;
                break;
            }

            *d++ = ch;
            break;

        case sw_quoted:
	  
            if (ch >= '0' && ch <= '9') {
                decoded = (u_char) (ch - '0');
                state = sw_quoted_second;
                break;
            }
	    
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                decoded = (u_char) (c - 'a' + 10);
                state = sw_quoted_second;
                break;
            }

            /* the invalid quoted character */
            bad++;
            state = sw_usual;
            *d++ = '%';
            *d++ = ch;
            break;

        case sw_quoted_second:

            state = sw_usual;

            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((decoded << 4) + ch - '0');

                if (type & NGX_UNESCAPE_REDIRECT) {
                    if (ch > '%' && ch < 0x7f) {
                        *d++ = ch;
                        break;
                    }

                    *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);

                    break;
                }

                *d++ = ch;

                break;
            }
	    
            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                ch = (u_char) ((decoded << 4) + c - 'a' + 10);

                if (type & NGX_UNESCAPE_URI) {
                    if (ch == '?') {
                        *d++ = ch;
                        goto done;
                    }

                    *d++ = ch;
                    break;
                }

                if (type & NGX_UNESCAPE_REDIRECT) {
                    if (ch == '?') {
                        *d++ = ch;
                        goto done;
                    }

                    if (ch > '%' && ch < 0x7f) {
                        *d++ = ch;
                        break;
                    }

                    *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);
                    break;
                }

                *d++ = ch;

                break;
            }
            /* the invalid quoted character */
            /* as it happened in the 2nd part of quoted character, 
                        we need to restore the decoded char as well. */
            *d++ = '%';
            *d++ = (0 >= decoded && decoded < 10)? (decoded + '0'): (decoded - 10 + 'a');
            *d++ = ch;
            bad++;
            break;
        }
    }

done:

    *dst = d;
    *src = s;
    
    return (bad);
}

/* 
** @description: Unescape routine.
** @para: ngx_str_t *str
** @return: uint (nullbytes+bad)
*/

int
ngx_yy_sec_waf_unescape(ngx_str_t *str) {
    u_char *dst, *src;
    u_int nullbytes = 0, bad = 0, i;
    
    dst = str->data;
    src = str->data;
        
    bad = ngx_yy_sec_waf_unescape_uri(&src, &dst, str->len, 0);

    str->len = src - str->data;

    /* tmp hack fix, avoid %00 & co (null byte) encoding :p */
    for (i = 0; i < str->len; i++) {
        if (str->data[i] == 0x0) {
    	    nullbytes++;
    	    str->data[i] = '0';
        }
    }

    return (nullbytes + bad);
}

