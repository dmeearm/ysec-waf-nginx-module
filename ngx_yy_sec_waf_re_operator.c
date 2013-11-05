/*
** @file: ngx_yy_sec_waf_re_operator.c
** @description: This is the rule engine's operators for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.11.05
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

/*
** @description: This function is called to parse str of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: void *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_str(ngx_conf_t *cf,
    ngx_str_t *tmp, void *rule_p)
{
    ngx_str_t *str;

    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t*) rule_p;

    if (!rule)
        return NGX_CONF_ERROR;

    str = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!str)
        return NGX_CONF_ERROR;

    str->data = tmp->data + ngx_strlen(STR);
    str->len = tmp->len - ngx_strlen(STR);

    rule->str = str;

    return NGX_CONF_OK;
}

/*
** @description: This function is called to excute str operator.
** @para: ngx_str_t *str
** @para: void *rule
** @return: RULE_MATCH or RULE_NO_MATCH if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_execute_str(ngx_http_request_t *r,
    ngx_str_t *str, void *rule_p)
{
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t*) rule_p;

    if (str == NULL && rule->mod) {
        return RULE_MATCH;
    }

    if (rule->str != NULL) {
        /* STR */
        if (ngx_strnstr(str->data, (char*) rule->str->data, str->len)) {
            return RULE_MATCH;
        }
    }

    return RULE_NO_MATCH;
}

/*
** @description: This function is called to parse regex of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: void *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_regex(ngx_conf_t *cf,
    ngx_str_t *tmp, void *rule_p)
{
    ngx_regex_compile_t *rgc;
    ngx_str_t            pattern;

    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t*) rule_p;

    pattern.data = tmp->data + ngx_strlen(REGEX);
    pattern.len = tmp->len - ngx_strlen(REGEX);

    rgc = ngx_pcalloc(cf->pool, sizeof(ngx_regex_compile_t));
    if (!rgc)
        return NGX_CONF_ERROR;

    rgc->options = PCRE_CASELESS|PCRE_MULTILINE;
    rgc->pattern = pattern;
    rgc->pool = cf->pool;
    rgc->err.len = 0;
    rgc->err.data = NULL;

    rule->regex = ngx_http_regex_compile(cf, rgc);
    if (rule->regex == NULL)
        return NGX_CONF_ERROR;

    return NGX_CONF_OK;
}

/*
** @description: This function is called to excute regex operator.
** @para: ngx_str_t *str
** @para: void *rule
** @return: RULE_MATCH or RULE_NO_MATCH if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_execute_regex(ngx_http_request_t *r,
    ngx_str_t *str, void *rule_p)
{
    int rc;

    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t*) rule_p;

    if (str == NULL && rule->mod) {
        return RULE_MATCH;
    }

    if (rule->regex != NULL) {
        /* REGEX */
        rc = ngx_http_regex_exec(r, rule->regex, str);
        
        if (rc == NGX_OK) {
            return RULE_MATCH;
        }

        return rc;
    }

    return NGX_ERROR;
}

/*
** @description: This function is called to parse eq of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: void *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_eq(ngx_conf_t *cf,
    ngx_str_t *tmp, void *rule_p)
{
    ngx_str_t *eq;

    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t*) rule_p;

    if (!rule)
        return NGX_CONF_ERROR;

    eq = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!eq)
        return NGX_CONF_ERROR;

    eq->data = tmp->data + ngx_strlen(EQ);
    eq->len = tmp->len - ngx_strlen(EQ);

    rule->eq = eq;

    return NGX_CONF_OK;
}

/*
** @description: This function is called to excute eq operator.
** @para: ngx_str_t *str
** @para: void *rule
** @return: RULE_MATCH or RULE_NO_MATCH if failed.
*/

static ngx_int_t
ngx_http_yy_sec_waf_execute_eq(ngx_http_request_t *r,
    ngx_str_t *str, void *rule_p)
{
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t*) rule_p;

    if (str == NULL && rule->mod) {
        return RULE_MATCH;
    }

    ngx_http_variable_value_t	 *vv;
    
    if (rule->var_index != NGX_CONF_UNSET) {
        vv = ngx_http_get_indexed_variable(r, rule->var_index);
    
        if (vv == NULL || vv->not_found) {
            return RULE_NO_MATCH;
        }
    
        if ((vv->len == rule->eq->len)
            && (ngx_memcmp(vv->data, rule->eq->data, vv->len) == 0))
        {
            return RULE_MATCH;
        }
    }

    return NGX_ERROR;
}

/*
** @description: This function is called to excute null operator.
** @para: ngx_str_t *str
** @para: void *rule
** @return: RULE_MATCH or RULE_NO_MATCH if failed.
*/

ngx_int_t
ngx_http_yy_sec_waf_execute_null(ngx_http_request_t *r,
    ngx_str_t *str, void *rule_p)
{
    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t*) rule_p;

    if (str == NULL && rule->mod) {
        return RULE_MATCH;
    }

    return RULE_NO_MATCH;
}

re_op_metadata op_metadata[] = {
    { "null", NULL, ngx_http_yy_sec_waf_execute_null }, // tmp hack for mod, remove it later.
    { "str", ngx_http_yy_sec_waf_parse_str, ngx_http_yy_sec_waf_execute_str },
    { "regex", ngx_http_yy_sec_waf_parse_regex, ngx_http_yy_sec_waf_execute_regex },
    { "eq", ngx_http_yy_sec_waf_parse_eq, ngx_http_yy_sec_waf_execute_eq },
    { NULL, NULL, NULL }
};
    
