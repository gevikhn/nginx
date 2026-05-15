#include <ngx_http_pqctls_module.h>


#define NGX_HTTP_PQCTLS_SEND_BUFFER_SIZE  (256 * 1024)
#define NGX_HTTP_PQCTLS_MAX_IOV           64


static void *ngx_http_pqctls_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_pqctls_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_pqctls_prepare_runtime_ctx(ngx_connection_t *c,
    ngx_http_pqctls_srv_conf_t *pscf);
static ngx_int_t ngx_http_pqctls_create_connection(ngx_connection_t *c,
    ngx_http_connection_t *hc, ngx_http_pqctls_srv_conf_t *pscf);
static ngx_int_t ngx_http_pqctls_load_file(ngx_conf_t *cf, ngx_str_t *path,
    ngx_str_t *content);
static void ngx_http_pqctls_cleanup(void *data);
static void ngx_http_pqctls_update_buffered(ngx_connection_t *c,
    ngx_http_pqctls_connection_t *pc);
static void ngx_http_pqctls_clear_handshake_timers(ngx_connection_t *c);
static void ngx_http_pqctls_arm_handshake_events(ngx_connection_t *c,
    ngx_http_pqctls_connection_t *pc, ngx_msec_t timeout);
static ngx_int_t ngx_http_pqctls_get_send_buffer(ngx_connection_t *c,
    ngx_http_pqctls_connection_t *pc);
static ngx_int_t ngx_http_pqctls_buf_empty(ngx_buf_t *b);
static ssize_t ngx_http_pqctls_sendv(ngx_connection_t *c,
    const pqctls_iovec_t *iov, size_t iovcnt);


static ngx_conf_enum_t ngx_http_pqctls_algorithms[] = {
    { ngx_string("ecdsa_kyber"), NGX_HTTP_PQCTLS_ALG_ECDSA_KYBER },
    { ngx_string("sm2_kyber"), NGX_HTTP_PQCTLS_ALG_SM2_KYBER },
    { ngx_null_string, 0 }
};


static ngx_command_t ngx_http_pqctls_commands[] = {

    { ngx_string("pqctls_certificate"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_pqctls_srv_conf_t, certificate),
      NULL },

    { ngx_string("pqctls_certificate_key"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_pqctls_srv_conf_t, certificate_key),
      NULL },

    { ngx_string("pqctls_client_certificate"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_pqctls_srv_conf_t, client_certificate),
      NULL },

    { ngx_string("pqctls_algorithm"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_pqctls_srv_conf_t, algorithm),
      &ngx_http_pqctls_algorithms },

    { ngx_string("pqctls_handshake_timeout"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_pqctls_srv_conf_t, handshake_timeout),
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_pqctls_module_ctx = {
    NULL,
    NULL,

    NULL,
    NULL,

    ngx_http_pqctls_create_srv_conf,
    ngx_http_pqctls_merge_srv_conf,

    NULL,
    NULL
};


ngx_module_t ngx_http_pqctls_module = {
    NGX_MODULE_V1,
    &ngx_http_pqctls_module_ctx,
    ngx_http_pqctls_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_pqctls_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_pqctls_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_pqctls_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->handshake_timeout = NGX_CONF_UNSET_MSEC;
    conf->algorithm = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_pqctls_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_pqctls_srv_conf_t *prev = parent;
    ngx_http_pqctls_srv_conf_t *conf = child;
    ngx_http_core_srv_conf_t   *cscf;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    ngx_conf_merge_str_value(conf->certificate, prev->certificate, "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    ngx_conf_merge_str_value(conf->client_certificate,
                             prev->client_certificate, "");
    ngx_conf_merge_msec_value(conf->handshake_timeout,
                              prev->handshake_timeout, 60000);
    ngx_conf_merge_uint_value(conf->algorithm, prev->algorithm,
                              NGX_HTTP_PQCTLS_ALG_ECDSA_KYBER);

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
        && ngx_http_pqctls_load_file(cf, &conf->certificate,
                                     &conf->certificate_data)
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->certificate_key_data.len == 0
        && ngx_http_pqctls_load_file(cf, &conf->certificate_key,
                                     &conf->certificate_key_data)
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->client_certificate_data.len == 0
        && ngx_http_pqctls_load_file(cf, &conf->client_certificate,
                                     &conf->client_certificate_data)
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_pqctls_load_file(ngx_conf_t *cf, ngx_str_t *path, ngx_str_t *content)
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
ngx_http_pqctls_prepare_runtime_ctx(ngx_connection_t *c,
    ngx_http_pqctls_srv_conf_t *pscf)
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
ngx_http_pqctls_cleanup(void *data)
{
    ngx_http_pqctls_connection_t  *pc = data;

    if (pc->session != NULL) {
        pqctls_session_free(pc->session);
        pc->session = NULL;
    }
}


static ngx_int_t
ngx_http_pqctls_create_connection(ngx_connection_t *c, ngx_http_connection_t *hc,
    ngx_http_pqctls_srv_conf_t *pscf)
{
    ngx_pool_cleanup_t            *cln;
    ngx_http_pqctls_connection_t  *pc;

    if (c->pqctls != NULL) {
        return NGX_OK;
    }

    if (ngx_http_pqctls_prepare_runtime_ctx(c, pscf) != NGX_OK) {
        return NGX_ERROR;
    }

    pc = ngx_pcalloc(c->pool, sizeof(ngx_http_pqctls_connection_t));
    if (pc == NULL) {
        return NGX_ERROR;
    }

    pc->http = hc;
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

    cln->handler = ngx_http_pqctls_cleanup;
    cln->data = pc;

    c->pqctls = pc;
    c->pqctls_cleanup = cln;
    c->recv = ngx_http_pqctls_recv;
    c->send = ngx_http_pqctls_send;
    c->send_chain = ngx_http_pqctls_send_chain;
    c->sendfile = 0;

    return NGX_OK;
}


static void
ngx_http_pqctls_update_buffered(ngx_connection_t *c,
    ngx_http_pqctls_connection_t *pc)
{
    if (pc != NULL && pc->session != NULL && pqctls_want_write(pc->session)) {
        c->buffered |= NGX_SSL_BUFFERED;
        return;
    }

    c->buffered &= ~NGX_SSL_BUFFERED;
}


static void
ngx_http_pqctls_clear_handshake_timers(ngx_connection_t *c)
{
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
}


static void
ngx_http_pqctls_arm_handshake_events(ngx_connection_t *c,
    ngx_http_pqctls_connection_t *pc, ngx_msec_t timeout)
{
    if (pqctls_want_read(pc->session)) {
        if (!c->read->timer_set) {
            ngx_add_timer(c->read, timeout);
        }

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }
    } else if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (pqctls_want_write(pc->session)) {
        if (!c->write->timer_set) {
            ngx_add_timer(c->write, timeout);
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }
    } else if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
}


static ngx_int_t
ngx_http_pqctls_get_send_buffer(ngx_connection_t *c,
    ngx_http_pqctls_connection_t *pc)
{
    if (pc->send_buffer != NULL) {
        return NGX_OK;
    }

    pc->send_buffer_size = NGX_HTTP_PQCTLS_SEND_BUFFER_SIZE;
    pc->send_buffer = ngx_pnalloc(c->pool, pc->send_buffer_size);
    if (pc->send_buffer == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_pqctls_buf_empty(ngx_buf_t *b)
{
    if (ngx_buf_in_memory(b) && b->pos < b->last) {
        return 0;
    }

    if (b->in_file && b->file_pos < b->file_last) {
        return 0;
    }

    return 1;
}


void
ngx_http_pqctls_handshake(ngx_event_t *rev)
{
    int                           rc;
    ngx_connection_t             *c;
    ngx_http_connection_t        *hc;
    ngx_http_pqctls_connection_t *pc;
    ngx_http_pqctls_srv_conf_t   *pscf;

    c = rev->data;
    hc = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http pqctls handshake");

    if (rev->timedout || c->write->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "client timed out during pqctls handshake");
        ngx_http_close_connection(c);
        return;
    }

    if (c->close) {
        ngx_http_close_connection(c);
        return;
    }

    pscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_pqctls_module);
    if (ngx_http_pqctls_create_connection(c, hc, pscf) != NGX_OK) {
        ngx_http_close_connection(c);
        return;
    }

    pc = c->pqctls;

    rc = pqctls_handshake_step(pc->session);
    ngx_http_pqctls_update_buffered(c, pc);

    if (rc == PQCTLS_OK) {
        ngx_http_pqctls_clear_handshake_timers(c);

        c->log->action = "waiting for request";
        ngx_reusable_connection(c, 1);
        ngx_http_start_request(c);
        return;
    }

    if (rc != PQCTLS_AGAIN) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "pqctls handshake failed: %s", pqctls_strerror(rc));
        ngx_http_close_connection(c);
        return;
    }

    ngx_reusable_connection(c, 0);
    ngx_http_pqctls_arm_handshake_events(c, pc, pscf->handshake_timeout);
}


ssize_t
ngx_http_pqctls_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int                           rc;
    size_t                        nread;
    ngx_http_pqctls_connection_t *pc;

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
ngx_http_pqctls_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    int                           rc;
    size_t                        nwritten;
    ngx_http_pqctls_connection_t *pc;

    pc = c->pqctls;
    if (pc == NULL || pc->session == NULL) {
        c->error = 1;
        return NGX_ERROR;
    }

    nwritten = 0;
    rc = pqctls_write(pc->session, buf, size, &nwritten);
    ngx_http_pqctls_update_buffered(c, pc);

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
ngx_http_pqctls_sendv(ngx_connection_t *c, const pqctls_iovec_t *iov,
    size_t iovcnt)
{
    int                           rc;
    size_t                        nwritten;
    ngx_http_pqctls_connection_t *pc;

    pc = c->pqctls;
    if (pc == NULL || pc->session == NULL) {
        c->error = 1;
        return NGX_ERROR;
    }

    nwritten = 0;
    rc = pqctls_writev(pc->session, iov, iovcnt, &nwritten);
    ngx_http_pqctls_update_buffered(c, pc);

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
ngx_http_pqctls_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    off_t                          sent;
    off_t                          fsize;
    size_t                         size;
    size_t                         total;
    size_t                         iovcnt;
    ssize_t                        n;
    ngx_buf_t                     *b;
    ngx_chain_t                   *cl;
    ngx_chain_t                   *scan;
    ngx_http_pqctls_connection_t  *pc;
    pqctls_iovec_t                 iov[NGX_HTTP_PQCTLS_MAX_IOV];

    pc = c->pqctls;
    if (pc == NULL || pc->session == NULL) {
        c->error = 1;
        return NGX_CHAIN_ERROR;
    }

    if (in == NULL) {
        n = ngx_http_pqctls_send(c, NULL, 0);
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
                n = ngx_http_pqctls_send(c, NULL, 0);
                if (n == NGX_ERROR) {
                    return NGX_CHAIN_ERROR;
                }
            }
            cl = cl->next;
            continue;
        }

        if (ngx_http_pqctls_buf_empty(b)) {
            cl = cl->next;
            continue;
        }

        if (ngx_buf_in_memory(b) && b->pos < b->last) {
            total = 0;
            iovcnt = 0;
            scan = cl;

            while (scan != NULL && iovcnt < NGX_HTTP_PQCTLS_MAX_IOV) {
                b = scan->buf;

                if (ngx_buf_special(b) || ngx_http_pqctls_buf_empty(b)
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

            n = ngx_http_pqctls_sendv(c, iov, iovcnt);

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

            if (ngx_http_pqctls_get_send_buffer(c, pc) != NGX_OK) {
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

            n = ngx_http_pqctls_send(c, pc->send_buffer, size);

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
