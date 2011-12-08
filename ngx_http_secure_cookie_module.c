

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>


typedef struct {
    ngx_http_complex_value_t  *variable;
    ngx_http_complex_value_t  *md5;
    ngx_http_complex_value_t  *md5_number;
    
    time_t                     expires;
} ngx_http_secure_cookie_conf_t;


static ngx_int_t ngx_http_secure_cookie_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_cookie_set_md5_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_cookie_md5_number(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_cookie_set_expires_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_secure_cookie_set_expires_base64_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_secure_cookie_create_conf(ngx_conf_t *cf);
static char *ngx_http_secure_cookie_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_secure_cookie_add_variables(ngx_conf_t *cf);


static ngx_command_t  ngx_http_secure_cookie_commands[] = {

    { ngx_string("secure_cookie"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_cookie_conf_t, variable),
      NULL },

    { ngx_string("secure_cookie_md5"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_cookie_conf_t, md5),
      NULL },

    { ngx_string("secure_cookie_md5_to_number"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_cookie_conf_t, md5_number),
      NULL },

    { ngx_string("secure_cookie_expires"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_secure_cookie_conf_t, expires),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_secure_cookie_module_ctx = {
    ngx_http_secure_cookie_add_variables,    /* preconfiguration */
    NULL,                                    /* postconfiguration */

    NULL,                                    /* create main configuration */
    NULL,                                    /* init main configuration */

    NULL,                                    /* create server configuration */
    NULL,                                    /* merge server configuration */

    ngx_http_secure_cookie_create_conf,      /* create location configuration */
    ngx_http_secure_cookie_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_secure_cookie_module = {
    NGX_MODULE_V1,
    &ngx_http_secure_cookie_module_ctx,      /* module context */
    ngx_http_secure_cookie_commands,         /* module directives */
    NGX_HTTP_MODULE,                         /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_secure_cookie_vars[] = {

    { ngx_string("secure_cookie"), NULL,
      ngx_http_secure_cookie_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("secure_cookie_set_md5"), NULL,
      ngx_http_secure_cookie_set_md5_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("secure_cookie_md5_number"), NULL,
      ngx_http_secure_cookie_md5_number, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("secure_cookie_set_expires"), NULL,
      ngx_http_secure_cookie_set_expires_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("secure_cookie_set_expires_base64"), NULL,
      ngx_http_secure_cookie_set_expires_base64_variable, 0,
      NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_int_t
ngx_http_secure_cookie_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                          hash_buf[16], md5_buf[16], time_buf[64];
    u_char                         *p, *last;
    ngx_str_t                       val, hash, time_dst, time_src;
    time_t                          expires;
    ngx_md5_t                       md5;
    ngx_http_secure_cookie_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_secure_cookie_module);

    if (conf->variable == NULL || conf->md5 == NULL) {
        goto not_found;
    }

    if (ngx_http_complex_value(r, conf->variable, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure cookie: \"%V\"", &val);

    last = val.data + val.len;

    p = ngx_strlchr(val.data, last, ',');
    expires = 0;

    if (p) {
        val.len = p++ - val.data;

        time_src.data = p;
        time_src.len = last - p;

        if (time_src.len > 64) {
            goto not_found;
        }

        time_dst.data = time_buf;
        time_dst.len = 64;

        if (ngx_decode_base64(&time_dst, &time_src) != NGX_OK) {
            goto not_found;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "secure time: \"%V\"", &time_dst);

        expires = ngx_http_parse_time(time_dst.data, time_dst.len);
        if (expires <= 0) {
            goto not_found;
        }
    }

    if (val.len > 24) {
        goto not_found;
    }

    hash.len = 16;
    hash.data = hash_buf;

    if (ngx_decode_base64(&hash, &val) != NGX_OK) {
        goto not_found;
    }

    if (hash.len != 16) {
        goto not_found;
    }

    if (ngx_http_complex_value(r, conf->md5, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure cookie md5: \"%V\"", &val);

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, val.data, val.len);
    ngx_md5_final(md5_buf, &md5);

    if (ngx_memcmp(hash_buf, md5_buf, 16) != 0) {
        goto not_found;
    }

    v->data = (u_char *) ((expires && expires < ngx_time()) ? "0" : "1");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_cookie_set_md5_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                           md5_buf[16];
    ngx_str_t                        res, val;
    ngx_md5_t                        md5;
    ngx_http_secure_cookie_conf_t   *sclcf;

    sclcf = ngx_http_get_module_loc_conf(r, ngx_http_secure_cookie_module);
    if (sclcf == NULL) {
        goto not_found;
    }

    if (ngx_http_complex_value(r, sclcf->md5, &val) != NGX_OK) {
        goto not_found;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure cookie set md5 base string: \"%V\"", &val);

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, val.data, val.len);
    ngx_md5_final(md5_buf, &md5);

    res.len = 24;
    res.data = ngx_pcalloc(r->pool, res.len);
    if (res.data == NULL) {
        goto not_found;
    }

    val.len = 16;
    val.data = md5_buf;
    ngx_encode_base64(&res, &val);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure cookie set md5 base64: \"%V\"", &res);

    v->len = res.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = res.data;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_cookie_md5_number(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                          *last;
    ngx_str_t                        number, val;
    ngx_uint_t                       hash;
    ngx_http_secure_cookie_conf_t   *sclcf;

    sclcf = ngx_http_get_module_loc_conf(r, ngx_http_secure_cookie_module);
    if (sclcf == NULL) {
        goto not_found;
    }

    if (sclcf->md5_number == NULL) {
        goto not_found;
    }

    if (ngx_http_complex_value(r, sclcf->md5_number, &val) != NGX_OK) {
        goto not_found;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure cookie md5 number base string: \"%V\"", &val);

    if (val.len == 0) {
        goto not_found;
    }

    hash = ngx_hash_key(val.data, val.len);

    number.len = 32;
    number.data = ngx_pcalloc(r->pool, number.len);
    if (number.data == NULL) {
        goto not_found;
    }

    last = ngx_snprintf(number.data, number.len, "%ud", hash);
    number.len = last - number.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure cookie md5 number: \"%V\"", &number);

    v->len = number.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = number.data;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_cookie_set_expires_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                         *last, *time;
    time_t                          expires;
    ngx_http_secure_cookie_conf_t  *sclcf;

    sclcf = ngx_http_get_module_loc_conf(r, ngx_http_secure_cookie_module);
    if (sclcf == NULL) {
        goto not_found;
    }

    time = ngx_palloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT"));
    if (time == NULL) {
        goto not_found;
    }

    expires = ngx_time() + sclcf->expires;

    last = ngx_http_cookie_time(time, expires);

    v->len = last - time;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = time;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_secure_cookie_set_expires_base64_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                         *last, t[32], *base64;
    time_t                          expires;
    ngx_str_t                       time, time_base64; 
    ngx_http_secure_cookie_conf_t  *sclcf;

    sclcf = ngx_http_get_module_loc_conf(r, ngx_http_secure_cookie_module);
    if (sclcf == NULL) {
        goto not_found;
    }

    base64 = ngx_palloc(r->pool, 64);
    if ( base64 == NULL) {
        goto not_found;
    }

    expires = ngx_time() + sclcf->expires;

    last = ngx_http_cookie_time(t, expires);

    time.data = t;
    time.len = last - t;

    time_base64.data = base64;
    time_base64.len = 64;

    ngx_encode_base64(&time_base64, &time);

    v->len = time_base64.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = time_base64.data;

    return NGX_OK;

not_found:

    v->not_found = 1;

    return NGX_OK;
}


static void *
ngx_http_secure_cookie_create_conf(ngx_conf_t *cf)
{
    ngx_http_secure_cookie_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_secure_cookie_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->variable   = NULL;
     *     conf->md5        = NULL;
     *     conf->md5_number = NULL;
     *     conf->expires    = 0;
     */

    conf->expires = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_secure_cookie_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_secure_cookie_conf_t *prev = parent;
    ngx_http_secure_cookie_conf_t *conf = child;

    if (conf->variable == NULL) {
        conf->variable = prev->variable;
    }

    if (conf->md5 == NULL) {
        conf->md5 = prev->md5;
    }

    if (conf->md5_number == NULL) {
        conf->md5_number = prev->md5_number;
    }

    ngx_conf_merge_sec_value(conf->expires, prev->expires, 24 * 60 * 60);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_secure_cookie_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_secure_cookie_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}
