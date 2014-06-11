
#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_tcp.h"

typedef struct ngx_tcp_echo_ctx_s {
    ngx_buf_t       *send_buffer;
} ngx_tcp_echo_ctx_t;

typedef struct ngx_tcp_echo_conf_s {
    size_t          read_buffer_size;
    size_t          send_buffer_size;

    ngx_msec_t      read_timeout;
    ngx_str_t       resp_str;
} ngx_tcp_echo_conf_t;

static void ngx_tcp_echo_init_session(ngx_tcp_session_t *s);
//static void ngx_tcp_echo_dummy_read_handler(ngx_tcp_session_t *s);
static void ngx_tcp_echo_dummy_write_handler(ngx_tcp_session_t *s);
static void ngx_tcp_echo_read_handler(ngx_tcp_session_t *s);
static int ngx_tcp_echo_read(ngx_tcp_session_t *s, ssize_t need);
static void ngx_tcp_echo_buf_done(ngx_buf_t *b, size_t s);

static void *ngx_tcp_echo_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_echo_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static const u_char HEAD_FLAG_FIREST = 0xAA;
static const u_char HEAD_FLAG_SECOND = 0x55;
static const u_char TAIL_FLAG_FIRST = 0xAB;
static const u_char TAIL_FLAG_SECOND = 0xAC;

static const size_t	echo_req_packet_head_len = 13;
static const size_t echo_req_packet_tail_len = 2;
static const size_t echo_resp_packet_head_len = 10;
static const size_t echo_resp_packet_tail_len = 2;

static ngx_tcp_protocol_t ngx_tcp_echo_protocol = {

	ngx_string("tcp_echo"),
	{0, 0, 0, 0},
	NGX_TCP_ECHO_PROTOCOL,
	ngx_tcp_echo_init_session,
	NULL,
	NULL,
	ngx_string("fuck you" CRLF)
};

static ngx_command_t ngx_tcp_echo_commands[] = {

    { ngx_string("echo_read_buffer_size"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_echo_conf_t, read_buffer_size),
      NULL },

    { ngx_string("echo_send_buffer_size"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_echo_conf_t, send_buffer_size),
      NULL },

    { ngx_string("echo_read_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_echo_conf_t, read_timeout),
      NULL },

    { ngx_string("echo_string"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_echo_conf_t, resp_str),
      NULL },

    ngx_null_command
};

static ngx_tcp_module_t ngx_tcp_echo_module_ctx = {
	&ngx_tcp_echo_protocol,
	NULL,

	NULL,
	NULL,

	ngx_tcp_echo_create_srv_conf,
	ngx_tcp_echo_merge_srv_conf
};

ngx_module_t ngx_tcp_echo_module = {
	NGX_MODULE_V1,
	&ngx_tcp_echo_module_ctx,
	ngx_tcp_echo_commands,
	NGX_TCP_MODULE,
	NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void 
ngx_tcp_echo_init_session(ngx_tcp_session_t *s)
{
    ngx_tcp_echo_conf_t             *ecsf;
    ngx_tcp_echo_ctx_t              *ctx;
    size_t                          buffer_size;

    ecsf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_echo_module);

	s->buffer = ngx_create_temp_buf(s->pool, ecsf->read_buffer_size);
    if (s->buffer == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    ctx = ngx_pcalloc(s->pool, sizeof(ngx_tcp_echo_ctx_t));
    if (NULL == ctx) {
        ngx_tcp_finalize_session(s);
        return;
    }

    if (ecsf->resp_str.len > 0 ) {
        buffer_size = echo_resp_packet_head_len + ecsf->resp_str.len + 
                        echo_resp_packet_tail_len;
    } else {
        buffer_size = ecsf->send_buffer_size;
    }

    ctx->send_buffer = ngx_create_temp_buf(s->pool, buffer_size);
    if (NULL == ctx->send_buffer) {
        ngx_tcp_finalize_session(s);
        return;
    }

    ngx_tcp_set_ctx(s, ctx, ngx_tcp_echo_module);

	s->write_event_handler = ngx_tcp_echo_dummy_write_handler;
	s->read_event_handler = ngx_tcp_echo_read_handler;

    s->read_event_handler(s);
}

static void 
ngx_tcp_echo_buf_done(ngx_buf_t *b, size_t s)
{
    b->pos += s;
    if (b->pos == b->last) {
        b->pos = b->start;
        b->last = b->start;
    }
}

static void 
ngx_tcp_echo_read_handler(ngx_tcp_session_t *s)
{
    ngx_tcp_echo_conf_t     *ecsf;
    ngx_tcp_echo_ctx_t      *ctx;
	u_char					*p;
	int 					n;
	ngx_buf_t         		*b;
	ssize_t 				packet_len;
	size_t 					resp_len;
	size_t 					packet_key;
	size_t 					packet_ver;
	size_t 					packet_session_id;
    ngx_str_t               packet_payload;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, 
                "echo read handler");

	if (s->connection->read->timedout) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "echo socket read timed out");
		ngx_tcp_finalize_session(s);
		return;
	}

	if (s->connection->read->timer_set) {
		ngx_del_timer(s->connection->read);
	}

    ecsf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_echo_module);

	n = ngx_tcp_echo_read(s, 2);
	if (n != NGX_OK) {
		return;
	}

	p = s->buffer->pos;
	while (p[0] != HEAD_FLAG_FIREST || p[1] != HEAD_FLAG_SECOND) {
        ngx_tcp_echo_buf_done(s->buffer, 1);
		n = ngx_tcp_echo_read(s, 1);
		if (n != NGX_OK) {
			return;
		}

		p = s->buffer->pos;
	}

    ngx_tcp_echo_buf_done(s->buffer, 2);

	n = ngx_tcp_echo_read(s, echo_req_packet_head_len - 2);
	if (n != NGX_OK) {
		return;
	}

	p = s->buffer->pos;
	packet_len = p[0] | p[1]<<8 | p[2]<<16 | p[3]<<24;
	packet_key = p[4] | p[5]<<8;
	packet_ver = p[6];
	packet_session_id = p[7] | p[8]<<8 | p[9]<<16 | p[10]<<24;
  
    ngx_tcp_echo_buf_done(s->buffer, echo_req_packet_head_len - 2);

	n = ngx_tcp_echo_read(s, packet_len - echo_req_packet_head_len);
	if (n != NGX_OK) {
		return;
	}

	p = s->buffer->pos + packet_len - echo_req_packet_head_len - echo_req_packet_tail_len;
	if (p[0] != TAIL_FLAG_FIRST || p[1] != TAIL_FLAG_SECOND) {    
        ngx_tcp_echo_buf_done(s->buffer, packet_len - echo_req_packet_head_len);
        
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, 
                                "packet tail flag error");
		return;
	}
    
    packet_payload.data = s->buffer->pos;
    packet_payload.len = packet_len - echo_req_packet_head_len - echo_req_packet_tail_len;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
                "tcp echo parse packet len=%uz, key=%uz, ver=%uz, session_id=%uzi, payload=\"%V\"",
                packet_len, packet_key, packet_ver, packet_session_id, packet_payload);

	resp_len = echo_resp_packet_head_len;
    if (ecsf->resp_str.len > 0 ) {
        resp_len += ecsf->resp_str.len;
    } else {
        resp_len += packet_payload.len;
    }
	resp_len += echo_resp_packet_tail_len;

    ctx = ngx_tcp_get_module_ctx(s, ngx_tcp_echo_module);
	b = ctx->send_buffer;

    *b->last++ = HEAD_FLAG_FIREST;
    *b->last++ = HEAD_FLAG_SECOND;
    *b->last++ = resp_len & 0x000000FF;
    *b->last++ = (resp_len >> 8) & 0x000000FF;
    *b->last++ = (resp_len >> 16) & 0x000000FF;
    *b->last++ = (resp_len >> 24) & 0x000000FF;
    *b->last++ = packet_key & 0x000000FF;
    *b->last++ = (packet_key >> 8) & 0x000000FF;
    *b->last++ = 0;
    *b->last++ = 0;
    if (ecsf->resp_str.len > 0) {
        b->last = ngx_cpymem(b->last, ecsf->resp_str.data, ecsf->resp_str.len);
    } else {
        b->last = ngx_cpymem(b->last, packet_payload.data, packet_payload.len);
    }

    *b->last++ = TAIL_FLAG_FIRST;
    *b->last++ = TAIL_FLAG_SECOND;

    n = s->connection->send(s->connection, b->pos, resp_len);
    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                        "tcp echo send resp error");
    	ngx_tcp_finalize_session(s);
    	return;
    }

    ngx_tcp_echo_buf_done(b, resp_len);
    ngx_tcp_echo_buf_done(s->buffer, packet_len - echo_req_packet_head_len);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, s->connection->log, 0, 
                    "tcp echo send resp sucessed!");

#if (NGX_STAT_STUB)
	(void) ngx_atomic_fetch_add(ngx_stat_requests, 1);
#endif

 	if (ngx_handle_read_event(s->connection->read, 0) != NGX_OK) {
 		ngx_tcp_finalize_session(s);
 		return;
 	}

 	if (!s->connection->read->timer_set) {
 		ngx_add_timer(s->connection->read, ecsf->read_timeout);
 	}

 	return;
}

static int 
ngx_tcp_echo_read(ngx_tcp_session_t *s, ssize_t need)
{
	ngx_connection_t		*c;
	ngx_event_t				*rev;
	ssize_t					size;
	ssize_t					n;
	ssize_t					need_len;
    ngx_tcp_echo_conf_t     *cesf;
    //ssize_t                 rest;
    //ssize_t                 len;

	c = s->connection;
	rev = c->read;

	size = s->buffer->last - s->buffer->pos;
	need_len = need;

	while ( size < need_len ) {
        /*
        rest = s->buffer->end - s->buffer->last;
        len = need_len - size;
		if (rest < len)
		{
			ngx_cpymem(s->buffer->start, s->buffer->pos, size);
			s->buffer->pos = s->buffer->start;
			s->buffer->last = s->buffer->pos + size;
		} 
        */

		n = c->recv(c, s->buffer->last, need_len - size);
		if (n == NGX_AGAIN) {
			if (!rev->timer_set) {
                cesf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_echo_module);
				ngx_add_timer(rev, cesf->read_timeout);
			}

			if (ngx_handle_read_event(rev, 0) != NGX_OK) {
				ngx_tcp_finalize_session(s);
				return NGX_ERROR;
			}

			return NGX_AGAIN;
		}

		if (n == NGX_ERROR) {
			ngx_tcp_finalize_session(s);
			return NGX_ERROR;
		}

		if (n == 0 ) {
			ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client closed connection");
        	ngx_tcp_finalize_session(s);
        	return NGX_ERROR;
		}

		s->buffer->last += n;
		size = s->buffer->last - s->buffer->pos;
	}

	return NGX_OK;
}


static void
ngx_tcp_echo_dummy_write_handler(ngx_tcp_session_t *s) 
{
    ngx_connection_t        *c;
    ngx_event_t             *wev;

    c = s->connection;
    wev = c->write;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "tcp echo dummy write handler: %d", c->fd);

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
    }
}

/*
static void
ngx_tcp_echo_dummy_read_handler(ngx_tcp_session_t *s) 
{
    ngx_connection_t    *c;
    ngx_event_t             *rev;

    c = s->connection;
    rev = c->read;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "tcp echo dummy read handler: %d", c->fd);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
    }
}
*/

static void * 
ngx_tcp_echo_create_srv_conf(ngx_conf_t *cf)
{
    ngx_tcp_echo_conf_t         *ecsf;

    ecsf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_echo_conf_t));
    if (NULL == ecsf) {
        return NULL;
    }

    ecsf->read_buffer_size = NGX_CONF_UNSET_SIZE;
    ecsf->send_buffer_size = NGX_CONF_UNSET_SIZE;
    ecsf->read_timeout = NGX_CONF_UNSET_MSEC;

    return ecsf;
}

static char *
ngx_tcp_echo_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_tcp_echo_conf_t *prev = parent;
    ngx_tcp_echo_conf_t *conf = child;

    if (conf->resp_str.len == 0) {
        conf->resp_str = prev->resp_str;
    }

    ngx_conf_merge_size_value(conf->read_buffer_size, prev->read_buffer_size, 1024);
    ngx_conf_merge_size_value(conf->send_buffer_size, prev->read_buffer_size, 1024);

    ngx_conf_merge_msec_value(conf->read_timeout, prev->read_timeout, 60000);
    
    return NGX_CONF_OK;
}
