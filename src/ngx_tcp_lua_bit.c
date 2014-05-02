
#include "ngx_tcp_lua_bit.h"
#include <stdint.h>

static char ngx_tcp_lua_bit_metatable_key;

static int ngx_tcp_lua_bit_new(lua_State *L);

typedef int32_t SBits;
typedef uint32_t UBits;

typedef union {
  lua_Number n;
#ifdef LUA_NUMBER_DOUBLE
  uint64_t b;
#else
  UBits b;
#endif
} BitNum;

/* Convert argument to bit type. */
static UBits 
barg(lua_State *L, int idx)
{
  BitNum bn;
  UBits b;
#if LUA_VERSION_NUM < 502
  bn.n = lua_tonumber(L, idx);
#else
  bn.n = luaL_checknumber(L, idx);
#endif
#if defined(LUA_NUMBER_DOUBLE)
  bn.n += 6755399441055744.0;  /* 2^52+2^51 */
#ifdef SWAPPED_DOUBLE
  b = (UBits)(bn.b >> 32);
#else
  b = (UBits)bn.b;
#endif
#elif defined(LUA_NUMBER_INT) || defined(LUA_NUMBER_LONG) || \
      defined(LUA_NUMBER_LONGLONG) || defined(LUA_NUMBER_LONG_LONG) || \
      defined(LUA_NUMBER_LLONG)
  if (sizeof(UBits) == sizeof(lua_Number))
    b = bn.b;
  else
    b = (UBits)(SBits)bn.n;
#elif defined(LUA_NUMBER_FLOAT)
#error "A 'float' lua_Number type is incompatible with this library"
#else
#error "Unknown number type, check LUA_NUMBER_* in luaconf.h"
#endif
#if LUA_VERSION_NUM < 502
  if (b == 0 && !lua_isnumber(L, idx)) {
    luaL_typerror(L, idx, "number");
  }
#endif
  return b;
}

/* Return bit type. */
#define BRET(b)  lua_pushnumber(L, (lua_Number)(SBits)(b)); return 1;

static int bit_tobit(lua_State *L) { BRET(barg(L, 1)) }
static int bit_bnot(lua_State *L) { BRET(~barg(L, 1)) }

#define BIT_OP(func, opr) \
  static int func(lua_State *L) { int i; UBits b = barg(L, 1); \
    for (i = lua_gettop(L); i > 1; i--) b opr barg(L, i); BRET(b) }
BIT_OP(bit_band, &=)
BIT_OP(bit_bor, |=)
BIT_OP(bit_bxor, ^=)

#define bshl(b, n)  (b << n)
#define bshr(b, n)  (b >> n)
#define bsar(b, n)  ((SBits)b >> n)
#define brol(b, n)  ((b << n) | (b >> (32-n)))
#define bror(b, n)  ((b << (32-n)) | (b >> n))
#define BIT_SH(func, fn) \
  static int func(lua_State *L) { \
    UBits b = barg(L, 1); UBits n = barg(L, 2) & 31; BRET(fn(b, n)) }
BIT_SH(bit_lshift, bshl)
BIT_SH(bit_rshift, bshr)
BIT_SH(bit_arshift, bsar)
BIT_SH(bit_rol, brol)
BIT_SH(bit_ror, bror)

static int 
bit_bswap(lua_State *L)
{
  UBits b = barg(L, 1);
  b = (b >> 24) | ((b >> 8) & 0xff00) | ((b & 0xff00) << 8) | (b << 24);
  BRET(b)
}

static int 
bit_tohex(lua_State *L)
{
  UBits b = barg(L, 1);
  SBits n = lua_isnone(L, 2) ? 8 : (SBits)barg(L, 2);
  const char *hexdigits = "0123456789abcdef";
  char buf[8];
  int i;
  if (n < 0) { n = -n; hexdigits = "0123456789ABCDEF"; }
  if (n > 8) n = 8;
  for (i = (int)n; --i >= 0; ) { buf[i] = hexdigits[b & 15]; b >>= 4; }
  lua_pushlstring(L, buf, (size_t)n);
  return 1;
}

void 
ngx_tcp_lua_inject_bit_api(lua_State *L)
{
	lua_createtable(L, 0, 2); /* ngx.bit */
	lua_pushcfunction(L, ngx_tcp_lua_bit_new);
	lua_setfield(L, -2, "new");

	lua_setfield(L, -2, "bit");

	lua_pushlightuserdata(L, &ngx_tcp_lua_bit_metatable_key);
	lua_createtable(L, 0, 12);

	lua_pushcfunction(L, bit_tobit);
	lua_setfield(L, -2, "tobit");

	lua_pushcfunction(L, bit_bnot);
	lua_setfield(L, -2, "bnot");

	lua_pushcfunction(L, bit_band);
	lua_setfield(L, -2, "band");

	lua_pushcfunction(L, bit_bor);
	lua_setfield(L, -2, "bor");

	lua_pushcfunction(L, bit_bxor);
	lua_setfield(L, -2, "bxor");

	lua_pushcfunction(L, bit_lshift);
	lua_setfield(L, -2, "lshift");

	lua_pushcfunction(L, bit_rshift);
	lua_setfield(L, -2, "rshift");

	lua_pushcfunction(L, bit_arshift);
	lua_setfield(L, -2, "arshift");

	lua_pushcfunction(L, bit_rol);
	lua_setfield(L, -2, "rol");

	lua_pushcfunction(L, bit_ror);
	lua_setfield(L, -2, "ror");

	lua_pushcfunction(L, bit_bswap);
	lua_setfield(L, -2, "bswap");

	lua_pushcfunction(L, bit_tohex);
	lua_setfield(L, -2, "tohex");

	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	lua_rawset(L, LUA_REGISTRYINDEX);
}


static int
ngx_tcp_lua_bit_new(lua_State *L)
{
	if (lua_gettop(L) != 0) {
		return luaL_error(L, "expecting zero arguments, but got %d",
                lua_gettop(L));
	}

	lua_createtable(L, 3, 1);
	lua_pushlightuserdata(L, &ngx_tcp_lua_bit_metatable_key);
	lua_rawget(L, LUA_REGISTRYINDEX);
	lua_setmetatable(L, -2);

	return 1;
}
