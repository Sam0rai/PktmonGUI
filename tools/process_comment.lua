-- Extract process metadata from pcapng frame comments.
local comment_field = Field.new("frame.comment")

local proc = Proto("procmeta", "Process Metadata")

local process_name = ProtoField.string(
    "procmeta.name", "Process Name"
)
local process_pid = ProtoField.uint32(
    "procmeta.pid", "Process ID", base.DEC
)
local process_fullpath = ProtoField.string(
    "procmeta.fullpath", "Process Full Path"
)
local process_description = ProtoField.string(
    "procmeta.description", "Process Description"
)

proc.fields = {
    process_name,
    process_pid,
    process_fullpath,
    process_description
}

local function trim(s)
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

-- Split "A for B" where B is a path: it starts with a drive letter,
-- a backslash (\Device\..., UNC) or "unknown path". A folder name may
-- itself contain " for ", so not every " for " is the separator.
local function split_paths(paths)
    local init = 1

    while true do
        local first, last = paths:find("%s+for%s+", init)

        if not first then
            return nil
        end

        local rest = paths:sub(last + 1)

        if rest:match("^%a:\\") or rest:match("^\\")
            or rest:match("^unknown path") then
            return trim(paths:sub(1, first - 1)), trim(rest)
        end

        init = last + 1
    end
end

function proc.dissector(buffer, pinfo, tree)
    -- Collect ALL comment values before extracting anything.
    local values = { comment_field() }
    local lines = {}

    for _, value in ipairs(values) do
        if value then
            lines[#lines + 1] = tostring(value)
        end
    end

    if #lines == 0 then
        return
    end

    local s = table.concat(lines, "\n")

    -- Extract each metadata line independently.
    local description = s:match(
        "Process:[ \t]*([^\r\n]*)"
    )
    local paths = s:match(
        "Process path:[ \t]*([^\r\n]*)"
    )

    if not description and not paths then
        return
    end

    if description then
        description = trim(description)
    end

    if paths then
        paths = trim(paths)
    end

    -- Default to the first process and its path.
    local selected = description
    local selected_path = paths

    -- If another process follows "for", select that process. Matching
    -- past the first "(PID n...)" keeps a " for " in the first
    -- process's own name from being taken for the separator.
    if description then
        local related = description:match(
            "^.-%(PID%s+%d+[^%)]*%)%s+for%s+(.+)$"
        )

        if related then
            selected = trim(related)

            -- Select the corresponding path after "for".
            if paths then
                local _, second_path = split_paths(paths)
                selected_path = second_path
            end
        end
    end

    local subtree = tree:add(proc)

    if description then
        subtree:add(process_description, description)
    end

    if selected then
        -- The name may contain spaces. PktmonGUI writes "unknown name"
        -- when it couldn't read the name; only the PID is known then.
        local name, pid = selected:match(
            "^(.-)%s*%(PID%s+(%d+)"
        )

        if name and name ~= "" and name ~= "unknown name" then
            subtree:add(process_name, name)
        end

        if pid then
            subtree:add(process_pid, tonumber(pid))
        end
    end

    if selected_path and selected_path ~= "" then
        subtree:add(process_fullpath, selected_path)
    end
end

register_postdissector(proc)
