/*
** @file: ngx_yy_sec_waf_parser.c
** @description: This is the rule parser for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.15
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

#define STR "str:"
#define REGEX "regex:"

typedef struct {
    char *type;
    void *(*parse)(ngx_conf_t *, ngx_str_t *, ngx_http_yy_sec_waf_rule_t *);
} ngx_http_yy_sec_waf_parser_t;

static void *ngx_http_yy_sec_waf_parse_str(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_regex(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);

static ngx_http_yy_sec_waf_parser_t rule_parser[] = {
    { STR, ngx_http_yy_sec_waf_parse_str},
    { REGEX, ngx_http_yy_sec_waf_parse_regex},
    { NULL, NULL}
};

/*
** @description: This function is called to parse str of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_str(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    ngx_str_t *str;

    if (!rule)
        return NGX_CONF_ERROR;

    str = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!str)
        return NGX_CONF_ERROR;

    str->data = tmp->data + strlen(STR);
    str->len = tmp->len - strlen(STR);

    rule->str = str;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0, "[waf] str=%V", rule->str);

    return NGX_CONF_OK;
}

/*
** @description: This function is called to parse regex of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_regex(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    ngx_regex_compile_t *rgc;
    ngx_str_t            pattern;

    pattern.data = tmp->data + strlen(REGEX);
    pattern.len = tmp->len - strlen(REGEX);

    rgc = ngx_pcalloc(cf->pool, sizeof(ngx_regex_compile_t));
    if (!rgc)
        return NGX_CONF_ERROR;

    rgc->options = PCRE_CASELESS|PCRE_MULTILINE;
    rgc->pattern = pattern;
    rgc->pool = cf->pool;
    rgc->err.len = 0;
    rgc->err.data = NULL;

    if (ngx_regex_compile(rgc) != NGX_OK)
        return NGX_CONF_ERROR;

    rule->rgc = rgc;

    return NGX_CONF_OK;
}

/*
** @description: This function is called to read configuration of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_command_t *cmd
** @para: void *conf
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

char *
ngx_http_yy_sec_waf_read_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_yy_sec_waf_loc_conf_t  *p = conf;

    ngx_uint_t        i;
    ngx_str_t        *value;
    ngx_http_yy_sec_waf_rule_t rule, *rule_p;

    value = cf->args->elts;
    ngx_memset(&rule, 0, sizeof(ngx_http_yy_sec_waf_rule_t));

    for (i = 0; rule_parser[i].parse; i++) {
        if (!ngx_strncmp(value[1].data, rule_parser[i].type, strlen(rule_parser[i].type))) {
            if (rule_parser[i].parse(cf, &value[1], &rule) != NGX_CONF_OK) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[waf] Failed parsing '%s'", value[1].data);
                return NGX_CONF_ERROR;
            }

            break;
        }
    }

    if (( rule.str != NULL) || ( rule.rgc != NULL)) {
        if (p->arg_rules == NULL) {
            p->arg_rules = ngx_array_create(cf->pool, 2, sizeof(ngx_http_yy_sec_waf_rule_t));

            if (p->arg_rules == NULL)
                return NGX_CONF_ERROR;
        }

        rule_p = ngx_array_push(p->arg_rules);

        if (rule_p == NULL)
            return NGX_CONF_ERROR;

        ngx_memcpy(rule_p, &rule, sizeof(ngx_http_yy_sec_waf_rule_t));
    }

    return NGX_CONF_OK;
}

