-- sync.lua — sync cycle for rmail thin client
--
-- Mirrors SyncManager.kt from the Android app.
-- Performs a full sync: manifest exchange, file download/upload, contacts.

local json = require("dkjson")

local sync = {}

-- Run a full sync cycle. Returns (result, error).
-- result is { new_messages = N, mailbox_name = "...", mailbox_path = "..." }
function sync.run(client, store)
    local state = store:read_sync_state()

    -- ── Compute local diffs ────────────────────────────────────────────

    -- Inbox: files that exist on disk vs state
    local disk_inbox = {}
    for _, name in ipairs(store:list_inbox()) do disk_inbox[name] = true end

    local deleted_inbox = {}
    for id, entry in pairs(state.inbox) do
        if not disk_inbox[entry.filename] then
            deleted_inbox[#deleted_inbox + 1] = {
                message_id = id,
                ["from"] = entry.from
            }
        end
    end

    -- Remove deleted entries from state
    for _, d in ipairs(deleted_inbox) do
        state.inbox[d.message_id] = nil
    end

    -- Outbox: files on disk vs state
    local disk_outbox = store:list_outbox()
    local disk_outbox_set = {}
    for _, name in ipairs(disk_outbox) do disk_outbox_set[name] = true end

    local new_outbox = {}
    for _, name in ipairs(disk_outbox) do
        if not state.outbox[name] then
            new_outbox[#new_outbox + 1] = name
        end
    end

    local deleted_outbox = {}
    for name in pairs(state.outbox) do
        if not disk_outbox_set[name] then
            deleted_outbox[#deleted_outbox + 1] = name
        end
    end

    -- Contacts hash
    local contacts_hash = store:contacts_hash()

    -- ── Build sync request ─────────────────────────────────────────────

    local inbox_map = {}
    for id, entry in pairs(state.inbox) do
        inbox_map[id] = entry.filename
    end

    local req = {
        inbox = inbox_map,
        deleted_inbox = deleted_inbox,
        outbox = disk_outbox,
        deleted_outbox = deleted_outbox,
        contacts_hash = contacts_hash
    }

    -- ── POST /api/sync ─────────────────────────────────────────────────

    local resp, err = client:sync(req)
    if not resp then return nil, err end

    local new_count = 0

    -- ── Apply server response ──────────────────────────────────────────

    -- Remove inbox files server says are gone
    if resp.remove_inbox then
        for _, id in ipairs(resp.remove_inbox) do
            local entry = state.inbox[id]
            if entry then
                store:delete_inbox(entry.filename)
                state.inbox[id] = nil
            end
        end
    end

    -- Download new inbox files
    if resp.fetch_inbox then
        for id, entry in pairs(resp.fetch_inbox) do
            local content, derr = client:download_file("inbox", entry.filename)
            if content then
                store:write_inbox(entry.filename, content)
                state.inbox[id] = { filename = entry.filename, from = entry.from }
                new_count = new_count + 1
            end
        end
    end

    -- Download new outbox files (created on desktop)
    if resp.fetch_outbox then
        for _, filename in ipairs(resp.fetch_outbox) do
            local content, derr = client:download_file("outbox", filename)
            if content then
                store:write_outbox(filename, content)
            end
        end
    end

    -- Upload new outbox files (created on this client)
    for _, filename in ipairs(new_outbox) do
        local content = store:read_outbox(filename)
        if content then
            client:upload_outbox_file(filename, content)
        end
    end

    -- Remove outbox files server marked as done
    -- (but skip files we just uploaded this cycle)
    local just_uploaded = {}
    for _, name in ipairs(new_outbox) do just_uploaded[name] = true end
    if resp.remove_outbox then
        for _, filename in ipairs(resp.remove_outbox) do
            if not just_uploaded[filename] then
                store:delete_outbox(filename)
            end
        end
    end

    -- ── Contacts sync ──────────────────────────────────────────────────

    if resp.contacts then
        -- Server sent contacts. If our hash differs, push ours (client wins
        -- if dirty). Otherwise accept server's version.
        if contacts_hash and contacts_hash ~= "" then
            -- We have local contacts — push them
            local local_contacts = store:read_contacts()
            if local_contacts and local_contacts ~= "" then
                client:post_contacts(local_contacts)
            end
        else
            -- No local contacts — accept server's
            store:write_contacts(resp.contacts)
        end
    end

    -- ── Update outbox state ────────────────────────────────────────────

    local new_outbox_state = {}
    for _, name in ipairs(store:list_outbox()) do
        new_outbox_state[name] = true
    end
    state.outbox = new_outbox_state
    state.contacts_hash = store:contacts_hash()

    -- ── Persist state ──────────────────────────────────────────────────

    store:write_sync_state(state)

    return {
        new_messages = new_count,
        mailbox_name = resp.mailbox_name,
        mailbox_path = resp.mailbox_path,
    }
end

return sync
