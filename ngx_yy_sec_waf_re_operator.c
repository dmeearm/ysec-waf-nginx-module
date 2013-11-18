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

    if (str == NULL) {
        return NGX_ERROR;
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

    if (str == NULL) {
        return NGX_ERROR;
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

    if (str == NULL) {
        return NGX_ERROR;
    }

    if ((str->len == rule->eq->len)
        && (ngx_memcmp(str->data, rule->eq->data, str->len) == 0))
    {
        return RULE_MATCH;
    }

    return RULE_NO_MATCH;
}


static re_op_metadata op_metadata[] = {
    { ngx_string("str"), ngx_http_yy_sec_waf_parse_str, ngx_http_yy_sec_waf_execute_str },
    { ngx_string("regex"), ngx_http_yy_sec_waf_parse_regex, ngx_http_yy_sec_waf_execute_regex },
    { ngx_string("eq"), ngx_http_yy_sec_waf_parse_eq, ngx_http_yy_sec_waf_execute_eq },
    { ngx_null_string, NULL, NULL }
};

ngx_int_t
yy_sec_waf_init_operators_in_hash(ngx_conf_t *cf,
    ngx_hash_t *operators_in_hash)
{
    ngx_array_t         operators;
    ngx_hash_key_t     *hk;
    ngx_hash_init_t     hash;
    re_op_metadata     *metadata;

    if (ngx_array_init(&operators, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (metadata = op_metadata; metadata->name.len; metadata++) {
        hk = ngx_array_push(&operators);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = metadata->name;
        hk->key_hash = ngx_hash_key_lc(metadata->name.data, metadata->name.len);
        hk->value = metadata;
    }

    hash.hash = operators_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "operators_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, operators.elts, operators.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

