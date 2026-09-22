/*
 * SPDX-License-Identifier: AGPL-3.0-or-later WITH AdditionRef-rmail-hook-exception
 * Copyright (C) 2026 ritz.  See LICENSE.
 *
 * rmail_kqueue.c — macOS/BSD outbox watcher for rmail
 *
 * ---------------------------------------------------------------------
 * A NOTE FROM THE PERSON WHOSE PROJECT THIS IS
 *
 * I don't have a Mac.  An LLM wrote this.  It might not work.  If it
 * doesn't, then... sorry?  Fix it yourself I guess.  Wish I could do
 * better for you.
 *
 * It has never been compiled, let alone run.  It is here because the
 * alternative was nothing being here, and because somebody with a Mac
 * and twenty minutes is in a much better position to finish it than I
 * am to start it again from scratch.  Patches extremely welcome.
 * ---------------------------------------------------------------------
 *
 * This is the macOS counterpart to rmail_inotify.c, which watches the
 * outbox so the daemon syncs the moment a file is saved rather than at
 * the next timer tick.  inotify is a Linux kernel interface and does
 * not exist here; kqueue is what BSD-derived systems have instead.
 *
 * It exposes exactly the interface rmail_inotify.c does, so the daemon
 * cannot tell which one it got:
 *
 *   init()                    -> fd (integer)
 *   add_watch(fd, path, mask) -> watch descriptor (integer)
 *   read(fd)                  -> list of event tables, or nil
 *   close(fd)
 *
 * WHY THIS IS EASIER THAN IT LOOKS
 *
 * inotify watches a directory and tells you which file inside it
 * changed.  kqueue watches an open file descriptor and, for a
 * directory, tells you only that something in it changed — not what.
 * That sounds like a problem and is not one: the daemon calls read()
 * purely to drain the queue and then sets a boolean meaning "go and
 * look at the outbox".  It never reads the event's filename, mask or
 * watch descriptor.  So the coarser answer kqueue gives is the whole
 * of what anybody wanted.
 *
 * The event tables are still built and returned, with a name of "",
 * because matching the other module's shape costs nothing and means a
 * future caller that does care will fail visibly rather than oddly.
 *
 * WHAT KQUEUE NEEDS THAT INOTIFY DOES NOT
 *
 * A watched path has to stay open.  inotify takes a path and hands
 * back a small integer; kqueue needs a live file descriptor for the
 * lifetime of the watch.  So add_watch() opens the path and keeps the
 * descriptor, returning it as the watch descriptor.  close() closes
 * the ones it knows about along with the kqueue itself.
 *
 * The kqueue descriptor is pollable with select(), which is what the
 * daemon's main loop does with it.  That is the property this whole
 * arrangement depends on and it is the reason kqueue is the right
 * answer here rather than FSEvents, which is higher level and wants
 * its own run loop.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <lua.h>
#include <lauxlib.h>

/*
 * Descriptors opened by add_watch, so close() can release them.
 *
 * A fixed array rather than anything cleverer because the daemon opens
 * exactly two watches — the outbox and the contacts file — and has done
 * since the watcher existed.  If that ever stops being true this will
 * refuse the third rather than silently leaking it.
 */
#define MAX_WATCHES 16
static int watched_fds[MAX_WATCHES];
static int watched_count = 0;

/* init() -> fd */
static int l_init(lua_State *L)
{
    int fd = kqueue();
    if (fd < 0) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }
    /* kqueue descriptors are not inherited across exec on macOS unless
     * asked, and the daemon spawns hook scripts.  Close them there. */
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    lua_pushinteger(L, fd);
    return 1;
}

/*
 * add_watch(kq, path, mask) -> wd
 *
 * The mask is the inotify-flavoured one the daemon passes.  It is
 * translated rather than used directly, because the two kernels name
 * these things differently and the daemon should not have to know
 * which one it is talking to.
 */
static int l_add_watch(lua_State *L)
{
    int kq = (int)luaL_checkinteger(L, 1);
    const char *path = luaL_checkstring(L, 2);
    lua_Integer mask = luaL_checkinteger(L, 3);

    if (watched_count >= MAX_WATCHES) {
        lua_pushnil(L);
        lua_pushstring(L, "too many watches");
        return 2;
    }

    /* O_EVTONLY asks for a descriptor usable for change notification
     * and nothing else; it does not count as having the file open for
     * the purposes of unmounting the volume, which matters when the
     * mailbox is on a removable drive. */
#ifdef O_EVTONLY
    int fd = open(path, O_EVTONLY);
#else
    int fd = open(path, O_RDONLY);
#endif
    if (fd < 0) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    /*
     * Translate the requested interest.  The daemon asks for creates,
     * deletes, writes and moves; kqueue spells those as WRITE (which
     * covers a directory gaining or losing an entry), DELETE, RENAME
     * and EXTEND.  Asking for all of them is both simpler and closer
     * to what the caller means, since it discards the detail anyway.
     */
    unsigned int fflags = NOTE_WRITE | NOTE_DELETE | NOTE_RENAME | NOTE_EXTEND;
    if (mask == 0) {
        fflags = NOTE_WRITE;
    }

    struct kevent change;
    EV_SET(&change, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, fflags, 0, NULL);

    if (kevent(kq, &change, 1, NULL, 0, NULL) < 0) {
        int saved = errno;
        close(fd);
        lua_pushnil(L);
        lua_pushstring(L, strerror(saved));
        return 2;
    }

    watched_fds[watched_count++] = fd;
    lua_pushinteger(L, fd);
    return 1;
}

/*
 * read(kq) -> {events} or nil
 *
 * Non-blocking, like the inotify one: a zero timeout means kevent
 * returns immediately with however many events were already queued.
 */
static int l_read(lua_State *L)
{
    int kq = (int)luaL_checkinteger(L, 1);
    struct kevent events[32];
    struct timespec zero = { 0, 0 };

    int n = kevent(kq, NULL, 0, events, 32, &zero);
    if (n <= 0) {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);
    for (int i = 0; i < n; i++) {
        lua_newtable(L);
        lua_pushinteger(L, (lua_Integer)events[i].ident);  lua_setfield(L, -2, "wd");
        lua_pushinteger(L, (lua_Integer)events[i].fflags); lua_setfield(L, -2, "mask");
        /* kqueue does not say which entry in a directory changed.  The
         * field exists so the shape matches; it is always empty. */
        lua_pushstring(L, "");                             lua_setfield(L, -2, "name");
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

/* close(kq) — and the descriptors add_watch opened */
static int l_close(lua_State *L)
{
    int kq = (int)luaL_checkinteger(L, 1);
    for (int i = 0; i < watched_count; i++) {
        close(watched_fds[i]);
    }
    watched_count = 0;
    close(kq);
    return 0;
}

int luaopen_rmail_kqueue(lua_State *L)
{
    lua_newtable(L);

    lua_pushcfunction(L, l_init);      lua_setfield(L, -2, "init");
    lua_pushcfunction(L, l_add_watch); lua_setfield(L, -2, "add_watch");
    lua_pushcfunction(L, l_read);      lua_setfield(L, -2, "read");
    lua_pushcfunction(L, l_close);     lua_setfield(L, -2, "close");

    /*
     * The same constant names the inotify module exports, so the daemon
     * can add them together without caring which kernel is underneath.
     * The values are kqueue's, and several collapse onto NOTE_WRITE
     * because kqueue does not distinguish a directory gaining an entry
     * from losing one — it says the directory changed and leaves the
     * rest to whoever looks.
     */
    lua_pushinteger(L, NOTE_WRITE);   lua_setfield(L, -2, "IN_CREATE");
    lua_pushinteger(L, NOTE_WRITE);   lua_setfield(L, -2, "IN_DELETE");
    lua_pushinteger(L, NOTE_WRITE);   lua_setfield(L, -2, "IN_MODIFY");
    lua_pushinteger(L, NOTE_RENAME);  lua_setfield(L, -2, "IN_MOVED_TO");
    lua_pushinteger(L, NOTE_WRITE);   lua_setfield(L, -2, "IN_CLOSE_WRITE");

    return 1;
}
