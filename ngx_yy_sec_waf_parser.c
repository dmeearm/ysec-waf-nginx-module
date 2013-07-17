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
#define GIDS "gids:"
#define MSG "msg:"
#define POS "pos:"

#define HEADER "HEADER"
#define BODY "BODY"
#define URL "URL"
#define ARGS "ARGS"
#define COOKIE "COOKIE"

typedef struct {
    char *type;
    void *(*parse)(ngx_conf_t *, ngx_str_t *, ngx_http_yy_sec_waf_rule_t *);
} ngx_http_yy_sec_waf_parser_t;

static void *ngx_http_yy_sec_waf_parse_str(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_regex(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_gids(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_msg(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_pos(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);

static ngx_http_yy_sec_waf_parser_t rule_parser[] = {
    { STR, ngx_http_yy_sec_waf_parse_str},
    { REGEX, ngx_http_yy_sec_waf_parse_regex},
    { GIDS, ngx_http_yy_sec_waf_parse_gids},
    { MSG, ngx_http_yy_sec_waf_parse_msg},
    { POS, ngx_http_yy_sec_waf_parse_pos},
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

    str->data = tmp->data + ngx_strlen(STR);
    str->len = tmp->len - ngx_strlen(STR);

    rule->str = str;

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

    if (ngx_regex_compile(rgc) != NGX_OK)
        return NGX_CONF_ERROR;

    rule->rgc = rgc;

    return NGX_CONF_OK;
}

/*
** @description: This function is called to parse gids of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_gids(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    ngx_str_t *gids;

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
** @description: This function is called to parse msg of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_msg(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    ngx_str_t *msg;

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
** @description: This function is called to parse pos of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_pos(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    char *tmp_ptr;
    
    tmp_ptr = (char*)tmp->data + ngx_strlen(POS);

    while (*tmp_ptr) {
        if (tmp_ptr[0] == '|')
            tmp_ptr++;
        /* match global zones */
        if (!ngx_strncmp(tmp_ptr, BODY, ngx_strlen(BODY))) {
            rule->body = 1;
            tmp_ptr += ngx_strlen(BODY);
            continue;
        } else if (!ngx_strncmp(tmp_ptr, HEADER, ngx_strlen(HEADER))) {
            rule->header = 1;
            tmp_ptr += ngx_strlen(HEADER);
            continue;
        } else if (!ngx_strncmp(tmp_ptr, URL, ngx_strlen(URL))) {
            rule->url = 1;
            tmp_ptr += ngx_strlen(URL);
            continue;
        } else if (!ngx_strncmp(tmp_ptr, ARGS, ngx_strlen(ARGS))) {
            rule->args = 1;
            tmp_ptr += ngx_strlen(ARGS);
            continue;
        } else if (!ngx_strncmp(tmp_ptr, COOKIE, ngx_strlen(COOKIE))) {
            rule->cookie = 1;
            tmp_ptr += ngx_strlen(COOKIE);
            continue;
        } else {
            return (NGX_CONF_ERROR);
        }
    }

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

    ngx_uint_t        i, n;
    ngx_str_t        *value;
    ngx_http_yy_sec_waf_rule_t rule, *rule_p;

    value = cf->args->elts;
    ngx_memset(&rule, 0, sizeof(ngx_http_yy_sec_waf_rule_t));

    for (n = 1; n < cf->args->nelts; n++) {
        for (i = 0; rule_parser[i].parse; i++) {
            if (!ngx_strncmp(value[n].data, rule_parser[i].type, ngx_strlen(rule_parser[i].type))) {
                if (rule_parser[i].parse(cf, &value[n], &rule) != NGX_CONF_OK) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[waf] Failed parsing '%s'", value[n].data);
                    return NGX_CONF_ERROR;
                }
    
                break;
            }
        }
    
    }

	if (rule.header) {
		if (p->header_rules == NULL) {
			p->header_rules = ngx_array_create(cf->pool, 2, sizeof(ngx_http_yy_sec_waf_rule_t));
	
			if (p->header_rules == NULL)
				return NGX_CONF_ERROR;
		}
	
		rule_p = ngx_array_push(p->header_rules);
	
		if (rule_p == NULL)
			return NGX_CONF_ERROR;
	
		ngx_memcpy(rule_p, &rule, sizeof(ngx_http_yy_sec_waf_rule_t));
	}

	if (rule.args) {
		if (p->args_rules == NULL) {
			p->args_rules = ngx_array_create(cf->pool, 2, sizeof(ngx_http_yy_sec_waf_rule_t));
	
			if (p->args_rules == NULL)
				return NGX_CONF_ERROR;
		}
	
		rule_p = ngx_array_push(p->args_rules);
	
		if (rule_p == NULL)
			return NGX_CONF_ERROR;
	
		ngx_memcpy(rule_p, &rule, sizeof(ngx_http_yy_sec_waf_rule_t));
	}

    return NGX_CONF_OK;
}

