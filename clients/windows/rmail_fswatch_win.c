/*
 * rmail_fswatch_win.c — Windows file/directory watcher
 *
 * Same API as rmail_inotify / rmail_fswatch:
 *
 *   fswatch.init()                    -> handle (as integer)
 *   fswatch.add_watch(h, path, mask)  -> watch descriptor
 *   fswatch.read(h)                   -> list of events or nil
 *   fswatch.close(h)
 *
 * Uses FindFirstChangeNotification for lightweight non-blocking directory
 * monitoring. For file-level events, uses ReadDirectoryChangesW.
 *
 * NOTE: This file only compiles on Windows. On other platforms, the client
 * falls back to interval-only sync.
 */

#ifdef _WIN32

#include <windows.h>
#include <stdlib.h>
#include <string.h>

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
    HANDLE handle;
    HANDLE dir_handle;
    char path[1024];
    OVERLAPPED overlapped;
    BYTE buffer[4096];
    int active;
} watches[MAX_WATCHES];
static int num_watches = 0;

/* init() -> dummy fd (we use watch handles directly) */
static int l_init(lua_State *L)
{
    /* Return a sentinel value — Windows doesn't use a single kqueue/epoll fd */
    lua_pushinteger(L, 1);
    return 1;
}

/* add_watch(h, path, mask) -> wd */
static int l_add_watch(lua_State *L)
{
    (void)luaL_checkinteger(L, 1);  /* ignored on Windows */
    const char *path = luaL_checkstring(L, 2);
    (void)luaL_checkinteger(L, 3);  /* mask for API compat */

    if (num_watches >= MAX_WATCHES) {
        lua_pushnil(L);
        lua_pushstring(L, "too many watches");
        return 2;
    }

    /* Open directory for overlapped ReadDirectoryChangesW */
    HANDLE dir = CreateFileA(path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL);

    if (dir == INVALID_HANDLE_VALUE) {
        /* Might be a file, not a directory — use FindFirstChangeNotification
           on the parent directory */
        HANDLE notif = FindFirstChangeNotificationA(path, FALSE,
            FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME);
        if (notif == INVALID_HANDLE_VALUE) {
            lua_pushnil(L);
            lua_pushstring(L, "cannot watch path");
            return 2;
        }
        int wd = num_watches;
        watches[wd].handle = notif;
        watches[wd].dir_handle = INVALID_HANDLE_VALUE;
        strncpy(watches[wd].path, path, sizeof(watches[wd].path) - 1);
        watches[wd].active = 1;
        num_watches++;
        lua_pushinteger(L, wd);
        return 1;
    }

    int wd = num_watches;
    watches[wd].handle = NULL;
    watches[wd].dir_handle = dir;
    strncpy(watches[wd].path, path, sizeof(watches[wd].path) - 1);
    memset(&watches[wd].overlapped, 0, sizeof(OVERLAPPED));
    watches[wd].overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    watches[wd].active = 0;

    /* Start async ReadDirectoryChangesW */
    BOOL ok = ReadDirectoryChangesW(dir, watches[wd].buffer,
        sizeof(watches[wd].buffer), FALSE,
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE |
        FILE_NOTIFY_CHANGE_CREATION,
        NULL, &watches[wd].overlapped, NULL);

    if (ok) watches[wd].active = 1;
    num_watches++;
    lua_pushinteger(L, wd);
    return 1;
}

/* read(h) -> {events} or nil (non-blocking) */
static int l_read(lua_State *L)
{
    (void)luaL_checkinteger(L, 1);
    int found = 0;

    lua_newtable(L);
    int idx = 1;

    for (int i = 0; i < num_watches; i++) {
        if (!watches[i].active) continue;

        if (watches[i].dir_handle != INVALID_HANDLE_VALUE) {
            /* ReadDirectoryChangesW — check overlapped result */
            DWORD bytes = 0;
            BOOL result = GetOverlappedResult(watches[i].dir_handle,
                &watches[i].overlapped, &bytes, FALSE);

            if (result && bytes > 0) {
                /* Parse FILE_NOTIFY_INFORMATION entries */
                FILE_NOTIFY_INFORMATION *info = (FILE_NOTIFY_INFORMATION *)watches[i].buffer;
                while (1) {
                    lua_newtable(L);
                    lua_pushinteger(L, i);
                    lua_setfield(L, -2, "wd");

                    int mask = 0;
                    switch (info->Action) {
                        case FILE_ACTION_ADDED:    mask = MASK_CREATE; break;
                        case FILE_ACTION_REMOVED:  mask = MASK_DELETE; break;
                        case FILE_ACTION_MODIFIED:  mask = MASK_MODIFY | MASK_CLOSE_WRITE; break;
                        case FILE_ACTION_RENAMED_NEW_NAME: mask = MASK_MOVED_TO; break;
                        default: mask = MASK_MODIFY; break;
                    }
                    lua_pushinteger(L, mask);
                    lua_setfield(L, -2, "mask");

                    /* Convert wide filename to UTF-8 */
                    char name[512] = "";
                    WideCharToMultiByte(CP_UTF8, 0, info->FileName,
                        info->FileNameLength / sizeof(WCHAR),
                        name, sizeof(name) - 1, NULL, NULL);
                    lua_pushstring(L, name);
                    lua_setfield(L, -2, "name");

                    lua_rawseti(L, -2, idx++);
                    found++;

                    if (info->NextEntryOffset == 0) break;
                    info = (FILE_NOTIFY_INFORMATION *)((BYTE *)info + info->NextEntryOffset);
                }

                /* Re-arm the watch */
                ResetEvent(watches[i].overlapped.hEvent);
                ReadDirectoryChangesW(watches[i].dir_handle, watches[i].buffer,
                    sizeof(watches[i].buffer), FALSE,
                    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE |
                    FILE_NOTIFY_CHANGE_CREATION,
                    NULL, &watches[i].overlapped, NULL);
            }
        } else {
            /* FindFirstChangeNotification path */
            DWORD wait = WaitForSingleObject(watches[i].handle, 0);
            if (wait == WAIT_OBJECT_0) {
                lua_newtable(L);
                lua_pushinteger(L, i);  lua_setfield(L, -2, "wd");
                lua_pushinteger(L, MASK_MODIFY | MASK_CLOSE_WRITE);
                lua_setfield(L, -2, "mask");
                lua_pushstring(L, "");  lua_setfield(L, -2, "name");
                lua_rawseti(L, -2, idx++);
                found++;
                FindNextChangeNotification(watches[i].handle);
            }
        }
    }

    if (found == 0) {
        lua_pop(L, 1);  /* remove the empty table */
        lua_pushnil(L);
    }
    return 1;
}

/* close(h) */
static int l_close(lua_State *L)
{
    (void)luaL_checkinteger(L, 1);
    for (int i = 0; i < num_watches; i++) {
        if (watches[i].dir_handle != INVALID_HANDLE_VALUE) {
            CancelIo(watches[i].dir_handle);
            CloseHandle(watches[i].overlapped.hEvent);
            CloseHandle(watches[i].dir_handle);
        }
        if (watches[i].handle) {
            FindCloseChangeNotification(watches[i].handle);
        }
    }
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

    lua_pushinteger(L, MASK_CREATE);      lua_setfield(L, -2, "IN_CREATE");
    lua_pushinteger(L, MASK_DELETE);      lua_setfield(L, -2, "IN_DELETE");
    lua_pushinteger(L, MASK_MODIFY);     lua_setfield(L, -2, "IN_MODIFY");
    lua_pushinteger(L, MASK_MOVED_TO);   lua_setfield(L, -2, "IN_MOVED_TO");
    lua_pushinteger(L, MASK_CLOSE_WRITE); lua_setfield(L, -2, "IN_CLOSE_WRITE");

    return 1;
}

#endif /* _WIN32 */
