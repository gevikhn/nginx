#include <ngx_stream_pqctls_module.h>


#define NGX_STREAM_PQCTLS_SEND_BUFFER_SIZE  (256 * 1024)
#define NGX_STREAM_PQCTLS_MAX_IOV           64


static ngx_int_t ngx_stream_pqctls_init(ngx_conf_t *cf);
static void *ngx_stream_pqctls_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_pqctls_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_stream_pqctls_prepare_runtime_ctx(ngx_connection_t *c,
    ngx_stream_pqctls_srv_conf_t *pscf);
static ngx_int_t ngx_stream_pqctls_create_connection(ngx_stream_session_t *s,
    ngx_stream_pqctls_srv_conf_t *pscf);
static ngx_int_t ngx_stream_pqctls_load_file(ngx_conf_t *cf, ngx_str_t *path,
    ngx_str_t *content);
static void ngx_stream_pqctls_cleanup(void *data);
static void ngx_stream_pqctls_update_buffered(ngx_connection_t *c,
    ngx_stream_pqctls_connection_t *pc);
static void ngx_stream_pqctls_clear_handshake_timers(ngx_connection_t *c);
static ngx_int_t ngx_stream_pqctls_arm_handshake_events(
    ngx_stream_session_t *s, ngx_stream_pqctls_connection_t *pc,
    ngx_msec_t timeout);
static void ngx_stream_pqctls_resume_session(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_pqctls_get_send_buffer(ngx_connection_t *c,
    ngx_stream_pqctls_connection_t *pc);
static ngx_int_t ngx_stream_pqctls_buf_empty(ngx_buf_t *b);
static ssize_t ngx_stream_pqctls_sendv(ngx_connection_t *c,
    const pqctls_iovec_t *iov, size_t iovcnt);


static ngx_conf_enum_t ngx_stream_pqctls_algorithms[] = {
    { ngx_string("ecdsa_kyber"), NGX_STREAM_PQCTLS_ALG_ECDSA_KYBER },
    { ngx_string("sm2_kyber"), NGX_STREAM_PQCTLS_ALG_SM2_KYBER },
    { ngx_null_string, 0 }
};


static ngx_command_t ngx_stream_pqctls_commands[] = {

    { ngx_string("pqctls_certificate"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_pqctls_srv_conf_t, certificate),
      NULL },

    { ngx_string("pqctls_certificate_key"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_pqctls_srv_conf_t, certificate_key),
      NULL },

    { ngx_string("pqctls_client_certificate"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_pqctls_srv_conf_t, client_certificate),
      NULL },

    { ngx_string("pqctls_algorithm"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_pqctls_srv_conf_t, algorithm),
      &ngx_stream_pqctls_algorithms },

    { ngx_string("pqctls_handshake_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_pqctls_srv_conf_t, handshake_timeout),
      NULL },

      ngx_null_command
};


static ngx_stream_module_t ngx_stream_pqctls_module_ctx = {
    NULL,
    ngx_stream_pqctls_init,

    NULL,
    NULL,

    ngx_stream_pqctls_create_srv_conf,
    ngx_stream_pqctls_merge_srv_conf
};


ngx_module_t ngx_stream_pqctls_module = {
    NGX_MODULE_V1,
    &ngx_stream_pqctls_module_ctx,
    ngx_stream_pqctls_commands,
    NGX_STREAM_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_stream_pqctls_init(ngx_conf_t *cf)
{
    ngx_stream_handler_pt        *h;
    ngx_stream_core_main_conf_t  *cmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_SSL_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_pqctls_handler;

    return NGX_OK;
}


static void *
ngx_stream_pqctls_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_pqctls_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_pqctls_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->handshake_timeout = NGX_CONF_UNSET_MSEC;
    conf->algorithm = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_stream_pqctls_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_pqctls_srv_conf_t *prev = parent;
    ngx_stream_pqctls_srv_conf_t *conf = child;
    ngx_stream_core_srv_conf_t   *cscf;

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);

    ngx_conf_merge_str_value(conf->certificate, prev->certificate, "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    ngx_conf_merge_str_value(conf->client_certificate,
                             prev->client_certificate, "");
    ngx_conf_merge_msec_value(conf->handshake_timeout,
                              prev->handshake_timeout, 60000);
    ngx_conf_merge_uint_value(conf->algorithm, prev->algorithm,
                              NGX_STREAM_PQCTLS_ALG_ECDSA_KYBER);

    if (!cscf->pqctls
        && conf->certificate.len == 0
        && conf->certificate_key.len == 0
        && conf->client_certificate.len == 0)
    {
        return NGX_CONF_OK;
    }

    if (conf->certificate.len == 0
        || conf->certificate_key.len == 0
        || conf->client_certificate.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pqctls_certificate, pqctls_certificate_key, "
                           "and pqctls_client_certificate must be set together");
        return NGX_CONF_ERROR;
    }

    if (ngx_conf_full_name(cf->cycle, &conf->certificate, 0) != NGX_OK
        || ngx_conf_full_name(cf->cycle, &conf->certificate_key, 0) != NGX_OK
        || ngx_conf_full_name(cf->cycle, &conf->client_certificate, 0) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->certificate_data.len == 0
        && ngx_stream_pqctls_load_file(cf, &conf->certificate,
                                       &conf->certificate_data)
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->certificate_key_data.len == 0
        && ngx_stream_pqctls_load_file(cf, &conf->certificate_key,
                                       &conf->certificate_key_data)
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->client_certificate_data.len == 0
        && ngx_stream_pqctls_load_file(cf, &conf->client_certificate,
                                       &conf->client_certificate_data)
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_pqctls_load_file(ngx_conf_t *cf, ngx_str_t *path, ngx_str_t *content)
{
    ngx_fd_t         fd;
    ngx_file_info_t  fi;
    size_t           offset;
    ssize_t          n;

    fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", path);
        return NGX_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed", path);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    content->len = (size_t) ngx_file_size(&fi);
    if (content->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "pqctls credential file \"%V\" is empty", path);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    content->data = ngx_pnalloc(cf->pool, content->len);
    if (content->data == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    for (offset = 0; offset < content->len; ) {
        n = ngx_read_fd(fd, content->data + offset, content->len - offset);
        if (n == -1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                               ngx_read_fd_n " \"%V\" failed", path);
            ngx_close_file(fd);
            return NGX_ERROR;
        }

        if (n == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unexpected EOF while reading \"%V\"", path);
            ngx_close_file(fd);
            return NGX_ERROR;
        }

        offset += (size_t) n;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_close_file_n " \"%V\" failed", path);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_pqctls_prepare_runtime_ctx(ngx_connection_t *c,
    ngx_stream_pqctls_srv_conf_t *pscf)
{
    int  rc;

    if (pscf->runtime_ctx != NULL) {
        return NGX_OK;
    }

    pscf->runtime_ctx = pqctls_ctx_new((int) pscf->algorithm);
    if (pscf->runtime_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "pqctls_ctx_new() failed");
        return NGX_ERROR;
    }

    rc = pqctls_ctx_load_root_cert_mem(pscf->runtime_ctx,
                                       pscf->client_certificate_data.data,
                                       pscf->client_certificate_data.len);
    if (rc != PQCTLS_OK) {
        goto failed;
    }

    rc = pqctls_ctx_load_server_cert_mem(pscf->runtime_ctx,
                                         pscf->certificate_data.data,
                                         pscf->certificate_data.len,
                                         pscf->certificate_key_data.data,
                                         pscf->certificate_key_data.len);
    if (rc != PQCTLS_OK) {
        goto failed;
    }

    return NGX_OK;

failed:
    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "pqctls runtime context initialization failed: %s",
                  pqctls_strerror(rc));
    pqctls_ctx_free(pscf->runtime_ctx);
    pscf->runtime_ctx = NULL;
    return NGX_ERROR;
}


static void
ngx_stream_pqctls_cleanup(void *data)
{
    ngx_stream_pqctls_connection_t  *pc = data;

    if (pc->session != NULL) {
        pqctls_session_free(pc->session);
        pc->session = NULL;
    }
}


static ngx_int_t
ngx_stream_pqctls_create_connection(ngx_stream_session_t *s,
    ngx_stream_pqctls_srv_conf_t *pscf)
{
    ngx_connection_t               *c;
    ngx_pool_cleanup_t             *cln;
    ngx_stream_pqctls_connection_t *pc;

    c = s->connection;

    if (c->pqctls != NULL) {
        return NGX_OK;
    }

    if (ngx_stream_pqctls_prepare_runtime_ctx(c, pscf) != NGX_OK) {
        return NGX_ERROR;
    }

    pc = ngx_pcalloc(c->pool, sizeof(ngx_stream_pqctls_connection_t));
    if (pc == NULL) {
        return NGX_ERROR;
    }

    pc->stream = s;
    pc->srv_conf = pscf;

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    pc->session = pqctls_session_new_server(pscf->runtime_ctx, c->fd);
    if (pc->session == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "pqctls_session_new_server() failed");
        return NGX_ERROR;
    }

    cln->handler = ngx_stream_pqctls_cleanup;
    cln->data = pc;

    c->pqctls = pc;
    c->pqctls_cleanup = cln;
    c->recv = ngx_stream_pqctls_recv;
    c->send = ngx_stream_pqctls_send;
    c->send_chain = ngx_stream_pqctls_send_chain;
    c->sendfile = 0;

    return NGX_OK;
}


static void
ngx_stream_pqctls_update_buffered(ngx_connection_t *c,
    ngx_stream_pqctls_connection_t *pc)
{
    if (pc != NULL && pc->session != NULL && pqctls_want_write(pc->session)) {
        c->buffered |= NGX_SSL_BUFFERED;
        return;
    }

    c->buffered &= ~NGX_SSL_BUFFERED;
}


static void
ngx_stream_pqctls_clear_handshake_timers(ngx_connection_t *c)
{
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
}


static ngx_int_t
ngx_stream_pqctls_arm_handshake_events(ngx_stream_session_t *s,
    ngx_stream_pqctls_connection_t *pc, ngx_msec_t timeout)
{
    ngx_connection_t  *c;

    c = s->connection;

    if (pqctls_want_read(pc->session)) {
        if (!c->read->timer_set) {
            ngx_add_timer(c->read, timeout);
        }

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    } else if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (pqctls_want_write(pc->session)) {
        if (!c->write->timer_set) {
            ngx_add_timer(c->write, timeout);
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    } else if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_pqctls_get_send_buffer(ngx_connection_t *c,
    ngx_stream_pqctls_connection_t *pc)
{
    if (pc->send_buffer != NULL) {
        return NGX_OK;
    }

    pc->send_buffer_size = NGX_STREAM_PQCTLS_SEND_BUFFER_SIZE;
    pc->send_buffer = ngx_pnalloc(c->pool, pc->send_buffer_size);
    if (pc->send_buffer == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_pqctls_buf_empty(ngx_buf_t *b)
{
    if (ngx_buf_in_memory(b) && b->pos < b->last) {
        return 0;
    }

    if (b->in_file && b->file_pos < b->file_last) {
        return 0;
    }

    return 1;
}


static void
ngx_stream_pqctls_resume_session(ngx_stream_session_t *s)
{
    ngx_connection_t  *c;

    c = s->connection;
    c->read->handler = ngx_stream_session_handler;
    c->write->handler = ngx_stream_session_handler;
    ngx_stream_core_run_phases(s);
}


ngx_int_t
ngx_stream_pqctls_handler(ngx_stream_session_t *s)
{
    int                            rc;
    ngx_connection_t              *c;
    ngx_stream_pqctls_connection_t *pc;
    ngx_stream_pqctls_srv_conf_t  *pscf;

    if (!s->pqctls) {
        return NGX_DECLINED;
    }

    c = s->connection;
    c->log->action = "PQCTLS handshaking";

    if (c->read->timedout || c->write->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "client timed out during pqctls handshake");
        return NGX_ERROR;
    }

    if (c->close) {
        return NGX_ERROR;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_pqctls_module);
    if (ngx_stream_pqctls_create_connection(s, pscf) != NGX_OK) {
        return NGX_ERROR;
    }

    pc = c->pqctls;

    if (pqctls_is_connected(pc->session)) {
        c->read->handler = ngx_stream_session_handler;
        c->write->handler = ngx_stream_session_handler;
        c->log->action = "initializing session";
        return NGX_OK;
    }

    rc = pqctls_handshake_step(pc->session);
    ngx_stream_pqctls_update_buffered(c, pc);

    if (rc == PQCTLS_OK) {
        ngx_stream_pqctls_clear_handshake_timers(c);
        c->read->handler = ngx_stream_session_handler;
        c->write->handler = ngx_stream_session_handler;
        c->log->action = "initializing session";
        return NGX_OK;
    }

    if (rc != PQCTLS_AGAIN) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "pqctls handshake failed: %s", pqctls_strerror(rc));
        return NGX_ERROR;
    }

    c->read->handler = ngx_stream_pqctls_handshake_handler;
    c->write->handler = ngx_stream_pqctls_handshake_handler;

    if (ngx_stream_pqctls_arm_handshake_events(s, pc,
                                               pscf->handshake_timeout)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}


void
ngx_stream_pqctls_handshake_handler(ngx_event_t *ev)
{
    int                            rc;
    ngx_connection_t              *c;
    ngx_stream_session_t          *s;
    ngx_stream_pqctls_connection_t *pc;
    ngx_stream_pqctls_srv_conf_t  *pscf;

    c = ev->data;
    s = c->data;

    if (s == NULL) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream pqctls handshake");

    if (c->read->timedout || c->write->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "client timed out during pqctls handshake");
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (c->close) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    pc = c->pqctls;
    if (pc == NULL || pc->session == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    pscf = ngx_stream_get_module_srv_conf(s, ngx_stream_pqctls_module);

    rc = pqctls_handshake_step(pc->session);
    ngx_stream_pqctls_update_buffered(c, pc);

    if (rc == PQCTLS_OK) {
        ngx_stream_pqctls_clear_handshake_timers(c);
        c->log->action = "initializing session";
        ngx_stream_pqctls_resume_session(s);
        return;
    }

    if (rc != PQCTLS_AGAIN) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "pqctls handshake failed: %s", pqctls_strerror(rc));
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_stream_pqctls_arm_handshake_events(s, pc,
                                               pscf->handshake_timeout)
        != NGX_OK)
    {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
}


ssize_t
ngx_stream_pqctls_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int                             rc;
    size_t                          nread;
    ngx_stream_pqctls_connection_t *pc;

    pc = c->pqctls;
    if (pc == NULL || pc->session == NULL) {
        c->error = 1;
        return NGX_ERROR;
    }

    nread = 0;
    rc = pqctls_read(pc->session, buf, size, &nread);

    if (rc == PQCTLS_OK) {
        return (ssize_t) nread;
    }

    if (rc == PQCTLS_AGAIN) {
        c->read->ready = 0;
        return NGX_AGAIN;
    }

    if (rc == PQCTLS_ERR_CLOSED) {
        c->read->eof = 1;
        c->read->ready = 0;
        return 0;
    }

    c->error = 1;
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "pqctls read failed: %s", pqctls_strerror(rc));
    return NGX_ERROR;
}


ssize_t
ngx_stream_pqctls_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    int                             rc;
    size_t                          nwritten;
    ngx_stream_pqctls_connection_t *pc;

    pc = c->pqctls;
    if (pc == NULL || pc->session == NULL) {
        c->error = 1;
        return NGX_ERROR;
    }

    nwritten = 0;
    rc = pqctls_write(pc->session, buf, size, &nwritten);
    ngx_stream_pqctls_update_buffered(c, pc);

    if (rc == PQCTLS_OK) {
        c->sent += nwritten;
        return (ssize_t) nwritten;
    }

    if (rc == PQCTLS_AGAIN) {
        c->write->ready = 0;
        if (nwritten > 0) {
            c->sent += nwritten;
            return (ssize_t) nwritten;
        }
        return NGX_AGAIN;
    }

    c->error = 1;
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "pqctls write failed: %s", pqctls_strerror(rc));
    return NGX_ERROR;
}


static ssize_t
ngx_stream_pqctls_sendv(ngx_connection_t *c, const pqctls_iovec_t *iov,
    size_t iovcnt)
{
    int                             rc;
    size_t                          nwritten;
    ngx_stream_pqctls_connection_t *pc;

    pc = c->pqctls;
    if (pc == NULL || pc->session == NULL) {
        c->error = 1;
        return NGX_ERROR;
    }

    nwritten = 0;
    rc = pqctls_writev(pc->session, iov, iovcnt, &nwritten);
    ngx_stream_pqctls_update_buffered(c, pc);

    if (rc == PQCTLS_OK) {
        c->sent += nwritten;
        return (ssize_t) nwritten;
    }

    if (rc == PQCTLS_AGAIN) {
        c->write->ready = 0;
        if (nwritten > 0) {
            c->sent += nwritten;
            return (ssize_t) nwritten;
        }
        return NGX_AGAIN;
    }

    c->error = 1;
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "pqctls writev failed: %s", pqctls_strerror(rc));
    return NGX_ERROR;
}


ngx_chain_t *
ngx_stream_pqctls_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    off_t                           sent;
    off_t                           fsize;
    size_t                          size;
    size_t                          total;
    size_t                          iovcnt;
    ssize_t                         n;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_chain_t                    *scan;
    ngx_stream_pqctls_connection_t *pc;
    pqctls_iovec_t                  iov[NGX_STREAM_PQCTLS_MAX_IOV];

    pc = c->pqctls;
    if (pc == NULL || pc->session == NULL) {
        c->error = 1;
        return NGX_CHAIN_ERROR;
    }

    if (in == NULL) {
        n = ngx_stream_pqctls_send(c, NULL, 0);
        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }
        return NULL;
    }

    sent = 0;

    for (cl = in; cl; ) {
        b = cl->buf;

        if (ngx_buf_special(b)) {
            if (b->flush || b->last_buf || b->sync) {
                n = ngx_stream_pqctls_send(c, NULL, 0);
                if (n == NGX_ERROR) {
                    return NGX_CHAIN_ERROR;
                }
            }
            cl = cl->next;
            continue;
        }

        if (ngx_stream_pqctls_buf_empty(b)) {
            cl = cl->next;
            continue;
        }

        if (ngx_buf_in_memory(b) && b->pos < b->last) {
            total = 0;
            iovcnt = 0;
            scan = cl;

            while (scan != NULL && iovcnt < NGX_STREAM_PQCTLS_MAX_IOV) {
                b = scan->buf;

                if (ngx_buf_special(b) || ngx_stream_pqctls_buf_empty(b)
                    || !ngx_buf_in_memory(b) || b->pos >= b->last)
                {
                    break;
                }

                size = (size_t) (b->last - b->pos);
                if (limit && sent + (off_t) total + (off_t) size > limit) {
                    size = (size_t) (limit - sent - (off_t) total);
                }

                iov[iovcnt].base = b->pos;
                iov[iovcnt].len = size;
                ++iovcnt;
                total += size;

                if (limit && sent + (off_t) total >= limit) {
                    break;
                }

                scan = scan->next;
            }

            n = ngx_stream_pqctls_sendv(c, iov, iovcnt);

            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR;
            }

            if (n == NGX_AGAIN) {
                return cl;
            }

            if (n == 0) {
                return cl;
            }

            cl = ngx_chain_update_sent(cl, n);
            sent += n;

            if ((size_t) n < total) {
                return cl;
            }

            if (limit && sent >= limit) {
                return cl;
            }

            continue;
        }

        while (b->in_file && b->file_pos < b->file_last) {
            if (limit && sent >= limit) {
                return cl;
            }

            if (ngx_stream_pqctls_get_send_buffer(c, pc) != NGX_OK) {
                return NGX_CHAIN_ERROR;
            }

            fsize = b->file_last - b->file_pos;
            if (fsize > (off_t) pc->send_buffer_size) {
                fsize = (off_t) pc->send_buffer_size;
            }

            if (limit && sent + fsize > limit) {
                fsize = limit - sent;
            }

            size = (size_t) fsize;
            n = ngx_read_file(b->file, pc->send_buffer, size, b->file_pos);

            if (n == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                              ngx_read_file_n " \"%s\" failed",
                              b->file->name.data);
                c->error = 1;
                return NGX_CHAIN_ERROR;
            }

            if ((size_t) n != size) {
                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              ngx_read_file_n " \"%s\" returned only %z of %uz",
                              b->file->name.data, n, size);
                c->error = 1;
                return NGX_CHAIN_ERROR;
            }

            n = ngx_stream_pqctls_send(c, pc->send_buffer, size);

            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR;
            }

            if (n == NGX_AGAIN) {
                return cl;
            }

            b->file_pos += n;
            sent += n;

            if ((size_t) n < size) {
                return cl;
            }

            if (limit && sent >= limit) {
                return cl;
            }
        }

        cl = cl->next;
    }

    return NULL;
}
