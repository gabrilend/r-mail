/*
 * rmail_inotify.c — Linux inotify wrapper for rmail
 *
 * Exposes three functions to Lua:
 *
 *   inotify.init()                    -> fd (integer)
 *   inotify.add_watch(fd, path, mask) -> watch descriptor (integer)
 *   inotify.read(fd)                  -> list of {wd, mask, name} tables, or nil if nothing ready
 *
 * The fd is created with IN_NONBLOCK so read() never blocks.
 * Designed to be polled from the existing socket.select() loop.
 *
 * Event mask constants are also exported (IN_CREATE, IN_DELETE, etc).
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/inotify.h>

#include <lua.h>
#include <lauxlib.h>

/* init() -> fd */
static int l_init(lua_State *L)
{
    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }
    lua_pushinteger(L, fd);
    return 1;
}

/* add_watch(fd, path, mask) -> wd */
static int l_add_watch(lua_State *L)
{
    int fd = (int)luaL_checkinteger(L, 1);
    const char *path = luaL_checkstring(L, 2);
    uint32_t mask = (uint32_t)luaL_checkinteger(L, 3);

    int wd = inotify_add_watch(fd, path, mask);
    if (wd < 0) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }
    lua_pushinteger(L, wd);
    return 1;
}

/* read(fd) -> {events} or nil
 * Non-blocking: returns nil immediately if no events pending. */
static int l_read(lua_State *L)
{
    int fd = (int)luaL_checkinteger(L, 1);
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));

    ssize_t len = read(fd, buf, sizeof(buf));
    if (len <= 0) {
        /* EAGAIN means no events ready (non-blocking) */
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);
    int idx = 1;
    const char *ptr = buf;
    while (ptr < buf + len) {
        const struct inotify_event *event = (const struct inotify_event *)ptr;
        lua_newtable(L);
        lua_pushinteger(L, event->wd);    lua_setfield(L, -2, "wd");
        lua_pushinteger(L, event->mask);  lua_setfield(L, -2, "mask");
        if (event->len > 0) {
            lua_pushstring(L, event->name);
        } else {
            lua_pushstring(L, "");
        }
        lua_setfield(L, -2, "name");
        lua_rawseti(L, -2, idx++);
        ptr += sizeof(struct inotify_event) + event->len;
    }
    return 1;
}

/* close(fd) */
static int l_close(lua_State *L)
{
    int fd = (int)luaL_checkinteger(L, 1);
    close(fd);
    return 0;
}

int luaopen_rmail_inotify(lua_State *L)
{
    lua_newtable(L);

    lua_pushcfunction(L, l_init);      lua_setfield(L, -2, "init");
    lua_pushcfunction(L, l_add_watch); lua_setfield(L, -2, "add_watch");
    lua_pushcfunction(L, l_read);      lua_setfield(L, -2, "read");
    lua_pushcfunction(L, l_close);     lua_setfield(L, -2, "close");

    /* event mask constants */
    lua_pushinteger(L, IN_CREATE);     lua_setfield(L, -2, "IN_CREATE");
    lua_pushinteger(L, IN_DELETE);     lua_setfield(L, -2, "IN_DELETE");
    lua_pushinteger(L, IN_MODIFY);    lua_setfield(L, -2, "IN_MODIFY");
    lua_pushinteger(L, IN_MOVED_TO);  lua_setfield(L, -2, "IN_MOVED_TO");
    lua_pushinteger(L, IN_CLOSE_WRITE); lua_setfield(L, -2, "IN_CLOSE_WRITE");

    return 1;
}
