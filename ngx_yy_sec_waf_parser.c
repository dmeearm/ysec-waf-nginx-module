/*
** @file: ngx_yy_sec_waf_parser.c
** @description: This is the rule parser for yy sec waf.
** @author: dw_liqi1<liqi1@yy.com>
** @date: 2013.07.15
** Copyright (C) YY, Inc.
*/

#include "ngx_yy_sec_waf.h"

extern ngx_http_yy_sec_waf_rule_t *mod_rules[];
extern ngx_uint_t mod_rules_num;

typedef struct {
    const char *type;
    void *(*parse)(ngx_conf_t *, ngx_str_t *, ngx_http_yy_sec_waf_rule_t *);
} ngx_http_yy_sec_waf_parser_t;

static void *ngx_http_yy_sec_waf_parse_str(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_regex(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_mod(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_gids(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_rule_id(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_msg(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_pos(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);
static void *ngx_http_yy_sec_waf_parse_level(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule);


static ngx_http_yy_sec_waf_parser_t rule_parser[] = {
    { STR, ngx_http_yy_sec_waf_parse_str},
    { REGEX, ngx_http_yy_sec_waf_parse_regex},
    { MOD, ngx_http_yy_sec_waf_parse_mod},
    { GIDS, ngx_http_yy_sec_waf_parse_gids},
    { ID, ngx_http_yy_sec_waf_parse_rule_id},
    { MSG, ngx_http_yy_sec_waf_parse_msg},
    { POS, ngx_http_yy_sec_waf_parse_pos},
    { LEVEL, ngx_http_yy_sec_waf_parse_level},
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

    rule->regex = ngx_http_regex_compile(cf, rgc);
    if (rule->regex == NULL)
        return NGX_CONF_ERROR;

    return NGX_CONF_OK;
}

/*
** @description: This function is called to parse mod of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_mod(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    ngx_str_t mod;

    if (!rule)
        return NGX_CONF_ERROR;

    mod.data = tmp->data + ngx_strlen(MOD);
    mod.len = tmp->len - ngx_strlen(MOD);

    if (!ngx_strncasecmp(mod.data, (u_char*)"off", mod.len)) {
        rule->mod = 0;
    } else if (!ngx_strncasecmp(mod.data, (u_char*)"on", mod.len)) {
        rule->mod = 1;
    } else {
        return NGX_CONF_ERROR;
    }

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
** @description: This function is called to parse rule id of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_rule_id(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    ngx_str_t *rule_id;

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
        } else if (!ngx_strncmp(tmp_ptr, URI, ngx_strlen(URI))) {
            rule->uri = 1;
            tmp_ptr += ngx_strlen(URI);
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
** @description: This function is called to parse level of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

static void *
ngx_http_yy_sec_waf_parse_level(ngx_conf_t *cf,
    ngx_str_t *tmp, ngx_http_yy_sec_waf_rule_t *rule)
{
    char *tmp_ptr;
    
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
                    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] Failed parsing '%s'", value[n].data);
                    return NGX_CONF_ERROR;
                }
    
                break;
            }
        }
    }

    for (i = 0; i < mod_rules_num; i++) {
        if (rule.rule_id == mod_rules[i]->rule_id) {
            ngx_memcpy(mod_rules[i], &rule, sizeof(ngx_http_yy_sec_waf_rule_t));
            break;
        }
    }


    if (rule.mod) {
        return NGX_CONF_OK;
    } else {
        if (rule.regex == NULL && rule.str == NULL) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "[ysec_waf] No regex or str for rule(id=%d)", rule.rule_id);
            return NGX_CONF_ERROR;
        }
    }

    if (rule.header) {
        if (p->header_rules == NULL) {
            p->header_rules = ngx_array_create(cf->pool, 1, sizeof(ngx_http_yy_sec_waf_rule_t));
            
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
            p->args_rules = ngx_array_create(cf->pool, 1, sizeof(ngx_http_yy_sec_waf_rule_t));
            
            if (p->args_rules == NULL)
                return NGX_CONF_ERROR;
        }
        
        rule_p = ngx_array_push(p->args_rules);
        
        if (rule_p == NULL)
            return NGX_CONF_ERROR;
        
        ngx_memcpy(rule_p, &rule, sizeof(ngx_http_yy_sec_waf_rule_t));
    }
    
    if (rule.uri) {
        if (p->uri_rules == NULL) {
            p->uri_rules = ngx_array_create(cf->pool, 1, sizeof(ngx_http_yy_sec_waf_rule_t));
            
            if (p->uri_rules == NULL)
                return NGX_CONF_ERROR;
        }
        
        rule_p = ngx_array_push(p->uri_rules);
        
        if (rule_p == NULL)
            return NGX_CONF_ERROR;
        
        ngx_memcpy(rule_p, &rule, sizeof(ngx_http_yy_sec_waf_rule_t));
    }

    return NGX_CONF_OK;
}

/*
** @description: This function is called to read denied url of yy sec waf.
** @para: ngx_conf_t *cf
** @para: ngx_str_t *tmp
** @para: ngx_http_yy_sec_waf_rule_t *rule
** @return: NGX_CONF_OK or NGX_CONF_ERROR if failed.
*/

char *
ngx_http_yy_sec_waf_read_du_loc_conf(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_yy_sec_waf_loc_conf_t *p = conf;
    ngx_str_t *value;

    value = cf->args->elts;
    if (value[1].len == 0)
        return NGX_CONF_ERROR;

    p->denied_url = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (!p->denied_url)
        return NGX_CONF_ERROR;

    p->denied_url->data = ngx_pcalloc(cf->pool, value[1].len+1);
    if (!p->denied_url->data)
        return NGX_CONF_ERROR;

    ngx_memcpy(p->denied_url->data, value[1].data, value[1].len);
    p->denied_url->len = value[1].len;

    return NGX_CONF_OK;
}

