/*
 * rmail_fswatch.c — macOS file/directory watcher using kqueue
 *
 * Provides the same API as rmail_inotify.so so the sync daemon code
 * works identically on Linux and macOS:
 *
 *   fswatch.init()                    -> fd
 *   fswatch.add_watch(fd, path, mask) -> watch descriptor
 *   fswatch.read(fd)                  -> list of events or nil
 *   fswatch.close(fd)
 *
 * The mask constants match rmail_inotify for compatibility:
 *   IN_CREATE, IN_DELETE, IN_MODIFY, IN_CLOSE_WRITE, IN_MOVED_TO
 *
 * Under the hood, kqueue watches file descriptors for vnode events.
 * For directories, we open the dir fd and watch for NOTE_WRITE (which
 * fires when files are added, removed, or renamed inside).
 * For files, we watch NOTE_WRITE and NOTE_ATTRIB.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/event.h>
#include <sys/time.h>

#include <lua.h>
#include <lauxlib.h>

/* Match rmail_inotify constants */
#define MASK_CREATE      256
#define MASK_DELETE       512
#define MASK_MODIFY       2
#define MASK_CLOSE_WRITE  8
#define MASK_MOVED_TO    128

#define MAX_WATCHES 32

static struct {
    int fd;       /* opened file/dir descriptor */
    char path[1024];
} watches[MAX_WATCHES];
static int num_watches = 0;

/* init() -> kqueue fd */
static int l_init(lua_State *L)
{
    int kq = kqueue();
    if (kq < 0) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }
    lua_pushinteger(L, kq);
    return 1;
}

/* add_watch(kq, path, mask) -> wd */
static int l_add_watch(lua_State *L)
{
    int kq = (int)luaL_checkinteger(L, 1);
    const char *path = luaL_checkstring(L, 2);
    /* mask is accepted for API compat but kqueue uses its own flags */
    (void)luaL_checkinteger(L, 3);

    if (num_watches >= MAX_WATCHES) {
        lua_pushnil(L);
        lua_pushstring(L, "too many watches");
        return 2;
    }

    int fd = open(path, O_RDONLY | O_EVTONLY);
    if (fd < 0) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }

    struct kevent change;
    EV_SET(&change, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
           NOTE_WRITE | NOTE_DELETE | NOTE_RENAME | NOTE_ATTRIB,
           0, NULL);

    if (kevent(kq, &change, 1, NULL, 0, NULL) < 0) {
        close(fd);
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }

    int wd = num_watches;
    watches[wd].fd = fd;
    strncpy(watches[wd].path, path, sizeof(watches[wd].path) - 1);
    watches[wd].path[sizeof(watches[wd].path) - 1] = '\0';
    num_watches++;

    lua_pushinteger(L, wd);
    return 1;
}

/* read(kq) -> {events} or nil (non-blocking) */
static int l_read(lua_State *L)
{
    int kq = (int)luaL_checkinteger(L, 1);
    struct kevent events[16];
    struct timespec timeout = { 0, 0 };  /* non-blocking */

    int n = kevent(kq, NULL, 0, events, 16, &timeout);
    if (n <= 0) {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);
    for (int i = 0; i < n; i++) {
        lua_newtable(L);
        /* Map kqueue ident (fd) back to watch descriptor */
        int wd = -1;
        for (int j = 0; j < num_watches; j++) {
            if (watches[j].fd == (int)events[i].ident) { wd = j; break; }
        }
        lua_pushinteger(L, wd);
        lua_setfield(L, -2, "wd");
        /* Map kqueue fflags to inotify-style mask */
        int mask = 0;
        if (events[i].fflags & NOTE_WRITE)  mask |= MASK_MODIFY | MASK_CLOSE_WRITE;
        if (events[i].fflags & NOTE_DELETE) mask |= MASK_DELETE;
        if (events[i].fflags & NOTE_RENAME) mask |= MASK_MOVED_TO;
        lua_pushinteger(L, mask);
        lua_setfield(L, -2, "mask");
        lua_pushstring(L, "");
        lua_setfield(L, -2, "name");
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

/* close(kq) */
static int l_close(lua_State *L)
{
    int kq = (int)luaL_checkinteger(L, 1);
    for (int i = 0; i < num_watches; i++) {
        if (watches[i].fd >= 0) close(watches[i].fd);
    }
    close(kq);
    num_watches = 0;
    return 0;
}

int luaopen_rmail_fswatch(lua_State *L)
{
    lua_newtable(L);

    lua_pushcfunction(L, l_init);      lua_setfield(L, -2, "init");
    lua_pushcfunction(L, l_add_watch); lua_setfield(L, -2, "add_watch");
    lua_pushcfunction(L, l_read);      lua_setfield(L, -2, "read");
    lua_pushcfunction(L, l_close);     lua_setfield(L, -2, "close");

    /* Event mask constants (matching rmail_inotify) */
    lua_pushinteger(L, MASK_CREATE);      lua_setfield(L, -2, "IN_CREATE");
    lua_pushinteger(L, MASK_DELETE);      lua_setfield(L, -2, "IN_DELETE");
    lua_pushinteger(L, MASK_MODIFY);     lua_setfield(L, -2, "IN_MODIFY");
    lua_pushinteger(L, MASK_MOVED_TO);   lua_setfield(L, -2, "IN_MOVED_TO");
    lua_pushinteger(L, MASK_CLOSE_WRITE); lua_setfield(L, -2, "IN_CLOSE_WRITE");

    return 1;
}
