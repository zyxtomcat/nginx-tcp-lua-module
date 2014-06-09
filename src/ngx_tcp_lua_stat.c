#include "ngx_tcp_lua_stat.h"

static int ngx_tcp_lua_add_request_stat(lua_State *L);

static int
ngx_tcp_lua_add_request_stat(lua_State *L)
{
#if (NGX_STAT_STUB)
	(void) ngx_atomic_fetch_add(ngx_stat_requests, 1);
#endif
    return 0;
}

void ngx_tcp_lua_inject_stat_api(lua_State *L)
{
	lua_pushcfunction(L, ngx_tcp_lua_add_request_stat);
	lua_setfield(L, -2, "add_request");
}
