/*
** @file: ngx_yy_sec_waf_re_action.c
** @description: This is the rule rule engine's actions for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.11.13
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

/*
** @description: This function is called to parse gids of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_gids(ngx_conf_t *cf,
    ngx_str_t *tmp, void *rule_p)
{
    ngx_str_t *gids;

    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t*) rule_p;

    if (!rule)
        return NGX_CONF_ERROR;

    gids = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!gids)
        return NGX_CONF_ERROR;

    gids->data = tmp->data + ngx_strlen(GIDS);
    gids->len = tmp->len - ngx_strlen(GIDS);

    rule->gids = gids;

    return NGX_CONF_OK;
}

/*
** @description: This function is called to parse rule id of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_rule_id(ngx_conf_t *cf,
    ngx_str_t *tmp, void *rule_p)
{
    ngx_str_t *rule_id;

    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t*) rule_p;

    if (!rule)
        return NGX_CONF_ERROR;

    rule_id = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!rule_id)
        return NGX_CONF_ERROR;

    rule_id->data = tmp->data + ngx_strlen(ID);
    rule_id->len = tmp->len - ngx_strlen(ID);

    rule->rule_id = ngx_atoi(rule_id->data, rule_id->len);

    return NGX_CONF_OK;
}

/*
** @description: This function is called to parse msg of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_msg(ngx_conf_t *cf,
    ngx_str_t *tmp, void *rule_p)
{
    ngx_str_t *msg;

    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t*) rule_p;

    if (!rule)
        return NGX_CONF_ERROR;

    msg = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!msg)
        return NGX_CONF_ERROR;

    msg->data = tmp->data + ngx_strlen(MSG);
    msg->len = tmp->len - ngx_strlen(MSG);

    rule->msg = msg;

    return NGX_CONF_OK;
}

/*
** @description: This function is called to parse level of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_level(ngx_conf_t *cf,
    ngx_str_t *tmp, void *rule_p)
{
    char *tmp_ptr;

    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t*) rule_p;

    tmp_ptr = (char*)tmp->data + ngx_strlen(LEVEL);

    while (*tmp_ptr) {
        if (tmp_ptr[0] == '|')
            tmp_ptr++;
        /* match global zones */
        if (!ngx_strncmp(tmp_ptr, BLOCK, ngx_strlen(BLOCK))) {
            rule->block = 1;
            tmp_ptr += ngx_strlen(BLOCK);
            continue;
        } else if (!ngx_strncmp(tmp_ptr, LOG, ngx_strlen(LOG))) {
            rule->log = 1;
            tmp_ptr += ngx_strlen(LOG);
            continue;
        } else if (!ngx_strncmp(tmp_ptr, ALLOW, ngx_strlen(ALLOW))) {
            rule->allow = 1;
            tmp_ptr += ngx_strlen(ALLOW);
            continue;
        } else {
            return (NGX_CONF_ERROR);
        }
    }

    return NGX_CONF_OK;
}

/*
** @description: This function is called to parse phase of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_phase(ngx_conf_t *cf,
    ngx_str_t *tmp, void *rule_p)
{
    ngx_str_t *phase;

    ngx_http_yy_sec_waf_rule_t *rule = (ngx_http_yy_sec_waf_rule_t*) rule_p;

    if (!rule)
        return NGX_CONF_ERROR;

    phase = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!phase)
        return NGX_CONF_ERROR;

    phase->data = tmp->data + ngx_strlen(PHASE);
    phase->len = tmp->len - ngx_strlen(PHASE);

    rule->phase = ngx_atoi(phase->data, phase->len);

    return NGX_CONF_OK;
}


re_action_metadata action_metadata[] = {
    { ngx_string(GIDS), ngx_http_yy_sec_waf_parse_gids},
    { ngx_string(ID), ngx_http_yy_sec_waf_parse_rule_id},
    { ngx_string(MSG), ngx_http_yy_sec_waf_parse_msg},
    { ngx_string(LEVEL), ngx_http_yy_sec_waf_parse_level},
    { ngx_string(PHASE), ngx_http_yy_sec_waf_parse_phase},
    { ngx_null_string, NULL}
};

