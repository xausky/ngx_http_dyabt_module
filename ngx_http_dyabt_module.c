#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define ngx_dyabt_add_timer(ev, timeout) \
    if (!ngx_exiting && !ngx_quit) ngx_add_timer(ev, (timeout))

typedef ngx_int_t(*ngx_http_dyabt_parser_ptr_t)(ngx_http_request_t *r);

typedef struct {
    ngx_int_t                      min;
    ngx_int_t                      max;
}ngx_http_dyabt_case_t;

typedef struct {
    ngx_http_dyabt_parser_ptr_t    parser;
    ngx_array_t                   *cases;
}ngx_http_dyabt_testing_t;

typedef struct {
    ngx_event_t                    timer;
    ngx_hash_t                    *hash;
    ngx_pool_t                    *pool;
    ngx_array_t                   *domains;
}ngx_http_dyabt_global_ctx_t;

typedef struct {
}ngx_http_dyabt_loc_conf_t;

typedef struct {
    ngx_str_t                     *domain;
    ngx_array_t                   *lengths;
    ngx_array_t                   *values;
    ngx_int_t                      values_count;
}ngx_http_dyabt_set_conf_t;

typedef struct {
    ngx_flag_t                     enable;
} ngx_http_dyabt_main_conf_t;

static ngx_int_t
ngx_http_dyabt_init_process(ngx_cycle_t *cycle);

static void
ngx_http_dyabt_on_timer(ngx_event_t *ev);

static char *
ngx_http_dyabt_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t
ngx_http_dyabt_set_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static void *
ngx_http_rewrite_create_loc_conf(ngx_conf_t *cf);

static char *
ngx_http_rewrite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *
ngx_http_dyabt_value(ngx_conf_t *cf, ngx_http_dyabt_set_conf_t *scf, ngx_str_t *value);

ngx_int_t
ngx_http_dyabt_uid_parser(ngx_http_request_t *r);

ngx_table_elt_t *
ngx_http_dyabt_search_headers(ngx_http_request_t *r, u_char *name, size_t len);

static char *
ngx_http_dyabt_interface(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *
ngx_http_dyabt_init_main_conf(ngx_conf_t *cf, void *conf);

static void *
ngx_http_dyabt_create_main_conf(ngx_conf_t *cf);

static ngx_http_dyabt_global_ctx_t ngx_http_dyabt_global_ctx;

static ngx_http_module_t  ngx_http_dyabt_module_ctx = {
    NULL,                             /* preconfiguration */
    NULL,                             /* postconfiguration */

    ngx_http_dyabt_create_main_conf,  /* create main configuration */
    ngx_http_dyabt_init_main_conf,    /* init main configuration */

    NULL,                             /* create server configuration */
    NULL,                             /* merge server configuration */

    ngx_http_rewrite_create_loc_conf, /* create location configuration */
    ngx_http_rewrite_merge_loc_conf   /* merge location configuration */
};

static ngx_command_t  ngx_http_dyabt_commands[] = {
    {
        ngx_string("dyabt_set"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        ngx_http_dyabt_set,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("dyabt_interface"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_dyabt_interface,
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

static char *
ngx_http_dyabt_interface(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_dyabt_main_conf_t  *dmcf;

    dmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_dyabt_module);
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    //TODO
    //clcf->handler = ngx_http_dyabt_interface_handler;
    dmcf->enable = 1;

    return NGX_CONF_OK;
}

static char *
ngx_http_dyabt_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_dyabt_main_conf_t  *dmcf = conf;
    if(dmcf->enable == NGX_CONF_UNSET){
        dmcf->enable = 0;
    }
    return NGX_CONF_OK;
}

static void *
ngx_http_dyabt_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_dyabt_main_conf_t  *dmcf;
    dmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dyabt_main_conf_t));
    if (dmcf == NULL) {
        return NULL;
    }
    dmcf->enable = NGX_CONF_UNSET;
    return dmcf;
}

static void *
ngx_http_rewrite_create_loc_conf(ngx_conf_t *cf){
    ngx_http_dyabt_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dyabt_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    return conf;
}

static char *
ngx_http_rewrite_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dyabt_loc_conf_t *prev = parent;
    ngx_http_dyabt_loc_conf_t *conf = child;
    return NGX_CONF_OK;
}

static char *
ngx_http_dyabt_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                            index;
    ngx_str_t                           *value;
    ngx_http_variable_t                 *v;
    ngx_http_dyabt_loc_conf_t           *lcf = conf;
    ngx_str_t                           *domain;
    ngx_http_dyabt_set_conf_t           *scf;
    value = cf->args->elts;
    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    value[1].len--;
    value[1].data++;
    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    scf = ngx_pnalloc(cf->pool, sizeof(ngx_http_dyabt_set_conf_t));
    scf->domain = ngx_pnalloc(cf->pool, sizeof(ngx_str_t));
    scf->domain->len = value[2].len;
    scf->domain->data = ngx_pnalloc(cf->pool, value[2].len);
    ngx_memcpy(scf->domain->data,value[2].data,scf->domain->len);
    if (ngx_http_dyabt_value(cf, scf, &value[2]) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    v->get_handler = ngx_http_dyabt_set_handler;
    v->data = (uintptr_t)scf;
    return NGX_CONF_OK;
}

static char *
ngx_http_dyabt_value(ngx_conf_t *cf, ngx_http_dyabt_set_conf_t *scf, ngx_str_t *value)
{
    ngx_int_t                              n;
    ngx_http_script_compile_t              sc;
    ngx_http_script_value_code_t          *val;
    ngx_http_script_complex_value_code_t  *complex;
    n = ngx_http_script_variables_count(value);
    if (n) {
        ngx_log_error(NGX_LOG_ERR,cf->log,0,"ngx_http_script_variables_count:%d",n);
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
        sc.cf = cf;
        sc.source = value;
        sc.lengths = &scf->lengths;
        sc.values = &scf->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }
    scf->values_count = n;
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_dyabt_set_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_int_t                           result;
    ngx_str_t                           value;
    ngx_http_dyabt_set_conf_t           *scf;
    ngx_http_dyabt_loc_conf_t           *lcf;
    ngx_http_dyabt_testing_t            *testing;
    ngx_http_dyabt_case_t               *cases;
    ngx_int_t                           size;
    ngx_int_t                           testing_result = -1;
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_dyabt_module);
    scf = (ngx_http_dyabt_set_conf_t*)data;
    if(scf->values_count){
        if (ngx_http_script_run(r, &value, scf->lengths->elts, 0, scf->values->elts) == NULL)
        {
            return NGX_ERROR;
        }
    }else{
        value = *(scf->domain);
    }
    result = 0;
    testing = ngx_hash_find(ngx_http_dyabt_global_ctx.hash,
        ngx_hash_key(value.data,value.len),
        value.data,value.len);
    if(testing){
        cases = testing->cases->elts;
        size = testing->cases->nelts;
        testing_result = testing->parser(r);
        for(result=0;result<size;result++){
            if(cases[result].min<=testing_result && cases[result].max>=testing_result){
                break;
            }
        }
        if(result>=size){
            result = 0;
        }else{
            result++;
        }
    }
    v->len = 2;
    v->data = ngx_pnalloc(r->pool, v->len);
    ngx_snprintf(v->data,2,"%d",result);
    return NGX_OK;
}

static ngx_int_t ngx_http_dyabt_init_process(ngx_cycle_t *cycle)
{
    ngx_hash_init_t             hash_init;
    ngx_int_t                   result;
    ngx_event_t                 *timer;
    ngx_pool_t                  *temp_pool;

    ngx_hash_key_t              *test_domain;
    ngx_http_dyabt_case_t       *test_case;
    ngx_http_dyabt_testing_t    *test_testing;
    ngx_str_t                   test_key = ngx_string("xausky.example.org");

    ngx_http_dyabt_global_ctx.pool = ngx_create_pool(
        (NGX_DEFAULT_POOL_SIZE*1024),cycle->log);
    ngx_http_dyabt_global_ctx.domains = ngx_pnalloc(
        ngx_http_dyabt_global_ctx.pool,
        sizeof(ngx_array_t));
    ngx_memzero(ngx_http_dyabt_global_ctx.domains,sizeof(ngx_array_t));
    result = ngx_array_init(ngx_http_dyabt_global_ctx.domains,
        ngx_http_dyabt_global_ctx.pool,
        16, sizeof(ngx_hash_key_t));
    if(result == NGX_ERROR){
        return NGX_ERROR;
    }
    /*
    * Temp test data;
    */
    test_testing = ngx_pnalloc(ngx_http_dyabt_global_ctx.pool,
        sizeof(ngx_http_dyabt_testing_t));
    test_testing->parser = ngx_http_dyabt_uid_parser;
    test_testing->cases = ngx_pnalloc(
        ngx_http_dyabt_global_ctx.pool,
        sizeof(ngx_array_t));
    result = ngx_array_init(test_testing->cases,
        ngx_http_dyabt_global_ctx.pool,
        4, sizeof(ngx_http_dyabt_case_t));
    if(result == NGX_ERROR){
        return NGX_ERROR;
    }
    test_case = ngx_array_push(test_testing->cases);
    test_case->min = 0;
    test_case->max = 10;
    test_domain = ngx_array_push(ngx_http_dyabt_global_ctx.domains);
    test_domain->key = test_key;
    test_domain->key_hash = ngx_hash_key(test_key.data,test_key.len);
    test_domain->value = test_testing;

    temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cycle->log);
    ngx_memzero(&hash_init,sizeof(ngx_hash_init_t));
    hash_init.key = ngx_hash_key;
    hash_init.max_size = 512;
    hash_init.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash_init.name = "ngx_http_dyabt_domains_hash_table";
    hash_init.pool = ngx_http_dyabt_global_ctx.pool;
    hash_init.temp_pool = temp_pool;
    result = ngx_hash_init(&hash_init,
        ngx_http_dyabt_global_ctx.domains->elts,
        ngx_http_dyabt_global_ctx.domains->nelts
    );
    ngx_http_dyabt_global_ctx.hash = hash_init.hash;
    timer = &ngx_http_dyabt_global_ctx.timer;
    ngx_memzero(timer,sizeof(ngx_event_t));
    timer->handler = ngx_http_dyabt_on_timer;
    timer->log = cycle->log;
    ngx_add_timer(timer,3000);
    return NGX_OK;
}

static void ngx_http_dyabt_on_timer(ngx_event_t *ev)
{
    ngx_log_error(NGX_LOG_ERR, ev->log, 0, "ngx_http_dyabt_on_timer");
    ngx_dyabt_add_timer(ev, 3000);
}

ngx_table_elt_t *
ngx_http_dyabt_search_headers(ngx_http_request_t *r, u_char *name, size_t len) {
    ngx_list_part_t            *part;
    ngx_table_elt_t            *h;
    ngx_uint_t                  i;

    /*
    Get the first part of the list. There is usual only one part.
    */
    part = &r->headers_in.headers.part;
    h = part->elts;

    /*
    Headers list array may consist of more than one part,
    so loop through all of it
    */
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                /* The last part, search is done. */
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        /*
        Just compare the lengths and then the names case insensitively.
        */
        if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0) {
            /* This header doesn't match. */
            continue;
        }

        /*
        Ta-da, we got one!
        Note, we'v stop the search at the first matched header
        while more then one header may fit.
        */
        return &h[i];
    }

    /*
    No headers was found
    */
    return NULL;
}

ngx_int_t
ngx_http_dyabt_uid_parser(ngx_http_request_t *r){
    ngx_table_elt_t *h;
    h = ngx_http_dyabt_search_headers(r,(u_char*)"X-UID",5);
    if(h==NULL){
        return -1;
    }
    return ngx_atoi(h->value.data,h->value.len);
}
