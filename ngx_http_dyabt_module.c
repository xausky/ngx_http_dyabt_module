#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define ngx_dyabt_add_timer(ev, timeout) \
    if (!ngx_exiting && !ngx_quit) ngx_add_timer(ev, (timeout))

typedef ngx_int_t(*ngx_http_dyabt_parser_ptr_t)(ngx_http_request_t *r);

typedef struct {
    ngx_int_t min;
    ngx_int_t max;
}ngx_http_dyabt_case_t;

typedef struct {
    ngx_http_dyabt_parser_ptr_t parser;
    ngx_array_t *cases;
}ngx_http_dyabt_testing_t;

typedef struct {
    ngx_event_t timer;
    ngx_array_t *vars;
    ngx_hash_init_t *hash;
}ngx_http_dyabt_global_ctx_t;

typedef struct {
    ngx_str_t  *key;        /* uintptr_t */
}ngx_http_dyabt_loc_conf_t;

static ngx_int_t ngx_http_dyabt_init_process(ngx_cycle_t *cycle);
static void ngx_http_dyabt_on_timer(ngx_event_t *ev);
static char *ngx_http_dyabt_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_dyabt_set_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_rewrite_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_rewrite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_http_dyabt_global_ctx_t ngx_http_dyabt_global_ctx;

static ngx_http_module_t  ngx_http_dyabt_module_ctx = {
    NULL,                             /* preconfiguration */
    NULL,                             /* postconfiguration */

    NULL,                             /* create main configuration */
    NULL,                             /* init main configuration */

    NULL,                             /* create server configuration */
    NULL,                             /* merge server configuration */

    ngx_http_rewrite_create_loc_conf, /* create location configuration */
    ngx_http_rewrite_merge_loc_conf   /* merge location configuration */
};

static ngx_command_t  ngx_http_dyabt_commands[] = {
    {
        ngx_string("dyabt_set"),
        NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                       |NGX_CONF_TAKE2,
        ngx_http_dyabt_set,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

ngx_module_t  ngx_http_dyabt_module = {
    NGX_MODULE_V1,
    &ngx_http_dyabt_module_ctx,    /* module context */
    ngx_http_dyabt_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_dyabt_init_process,   /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *ngx_http_rewrite_create_loc_conf(ngx_conf_t *cf){
    ngx_http_dyabt_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dyabt_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->key = NGX_CONF_UNSET_PTR;
    return conf;
}

static char *ngx_http_rewrite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dyabt_loc_conf_t *prev = parent;
    ngx_http_dyabt_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->key,prev->key,NGX_CONF_UNSET_PTR);
    return NGX_CONF_OK;
}

static char *ngx_http_dyabt_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                            index;
    ngx_str_t                           *value;
    ngx_http_variable_t                 *v;
    ngx_http_dyabt_loc_conf_t           *lcf = conf;
    value = cf->args->elts;
    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    //去掉$
    value[1].len--;
    value[1].data++;
    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }
    v->get_handler = ngx_http_dyabt_set_handler;
    lcf->key = ngx_pnalloc(cf->pool, sizeof(ngx_str_t));
    lcf->key->len = value[2].len;
    lcf->key->data = ngx_pnalloc(cf->pool, value[2].len);
    ngx_snprintf(lcf->key->data,lcf->key->len,"%V",&value[2]);
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_dyabt_set_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_dyabt_loc_conf_t           *lcf;
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_dyabt_module);
    ngx_str_t *src = lcf->key;
    v->len = src->len + 2;
    v->data = ngx_pnalloc(r->pool, v->len);
    ngx_snprintf(v->data,v->len,"0.%V",src);
    return NGX_OK;
}

static ngx_int_t ngx_http_dyabt_init_process(ngx_cycle_t *cycle)
{
    ngx_event_t                 *timer;
    timer = &ngx_http_dyabt_global_ctx.timer;
    ngx_memzero(timer,sizeof(ngx_event_t));
    timer->handler = ngx_http_dyabt_on_timer;
    timer->log = cycle->log;
    ngx_add_timer(timer,1000);
    return NGX_OK;
}

static void ngx_http_dyabt_on_timer(ngx_event_t *ev)
{
    ngx_log_error(NGX_LOG_ERR, ev->log, 0, "ngx_http_dyabt_on_timer");
    ngx_dyabt_add_timer(ev, 1000);
}
