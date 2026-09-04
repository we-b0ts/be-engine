load_runtime_spec() {
    local inspect_json=$1
    local mount_mode=$2
    local environment_mode=$3
    local launch_mode=$4
    [[ "$launch_mode" == exact || "$launch_mode" == image ]] || {
        printf 'error: unsupported container launch mode %s\n' "$launch_mode" >&2
        return 1
    }
    runtime_args=(--platform linux/amd64)
    runtime_command=()
    if [[ "$launch_mode" == exact ]]; then
        local workdir configured_user
        workdir=$(jq -r '.[0].Config.WorkingDir // empty' <<<"$inspect_json")
        [[ -z "$workdir" ]] || runtime_args+=(--workdir "$workdir")
        configured_user=$(jq -r '.[0].Config.User // empty' <<<"$inspect_json")
        [[ -z "$configured_user" ]] || runtime_args+=(--user "$configured_user")
        [[ "$(jq -r '.[0].HostConfig.Privileged // false' <<<"$inspect_json")" != true ]] || runtime_args+=(--privileged)
    fi
    [[ "$(jq -r '.[0].HostConfig.ReadonlyRootfs // false' <<<"$inspect_json")" != true ]] || runtime_args+=(--read-only)
    [[ "$(jq -r '.[0].HostConfig.Init // false' <<<"$inspect_json")" != true ]] || runtime_args+=(--init)

    local -a entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].Config.Env[]? | ., "\u0000"' <<<"$inspect_json")
    local entry name
    for entry in "${entries[@]}"; do
        name=${entry%%=*}
        [[ "$name" == HOSTNAME ]] && continue
        if [[ "$environment_mode" == recording ]] &&
            [[ "$name" == RUN_COMMAND || "$name" == MESH_CONNECT_HOST || "$name" == JAVA_TOOL_OPTIONS ]]; then
            continue
        fi
        runtime_args+=(--env "$entry")
    done

    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].HostConfig.Ulimits[]? | (.Name + "=" + (.Soft|tostring) + ":" + (.Hard|tostring)), "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--ulimit "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].HostConfig.CapAdd[]? | ., "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--cap-add "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].HostConfig.CapDrop[]? | ., "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--cap-drop "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].HostConfig.GroupAdd[]? | ., "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--group-add "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].HostConfig.SecurityOpt[]? | ., "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--security-opt "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].Config.Labels // {} | to_entries[] | (.key + "=" + .value), "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--label "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.[0].HostConfig.Sysctls // {} | to_entries[] | (.key + "=" + .value), "\u0000"' <<<"$inspect_json")
    for entry in "${entries[@]}"; do runtime_args+=(--sysctl "$entry"); done

    local source destination writable volume
    while IFS=$'\t' read -r source destination writable volume; do
        [[ -n "$destination" ]] || continue
        validate_container_mount_path "$destination" || {
            printf 'error: container has unsupported mount destination %s\n' "$destination" >&2
            return 1
        }
        case "$destination" in
            /etc/resolv.conf|/etc/hosts|/etc/hostname) continue ;;
        esac
        if [[ -n "$volume" && "$volume" != null ]]; then source=$volume; fi
        if [[ "$mount_mode" == recording ]]; then
            resolve_recording_mount_source "$destination" "$writable" "$source"
            source=$prepared_mount_source
            writable=$prepared_mount_writable
        fi
        if [[ "$writable" == true ]]; then
            runtime_args+=(--volume "${source}:${destination}:rw")
        else
            runtime_args+=(--volume "${source}:${destination}:ro")
        fi
    done < <(jq -r '.[0].Mounts[]? | [.Source, .Destination, .RW, (.Name // "")] | @tsv' <<<"$inspect_json")
    [[ "$mount_mode" != recording ]] || append_source_runtime_output_args

    if [[ "$launch_mode" == exact ]]; then
        entries=()
        mapfile -d '' -t entries < <(jq -j '.[0].Config.Entrypoint[]? | ., "\u0000"' <<<"$inspect_json")
        if ((${#entries[@]} > 0)); then
            runtime_args+=(--entrypoint "${entries[0]}")
            ((${#entries[@]} == 1)) || runtime_command+=("${entries[@]:1}")
        fi
        entries=()
        mapfile -d '' -t entries < <(jq -j '.[0].Config.Cmd[]? | ., "\u0000"' <<<"$inspect_json")
        runtime_command+=("${entries[@]}")
    fi
}

load_source_runtime_spec() {
    local runtime_file=$1
    runtime_args=(--platform linux/amd64)
    runtime_command=()
    [[ "$(jq -r '.security.privileged' "$runtime_file")" != true ]] || runtime_args+=(--privileged)
    [[ "$(jq -r '.security.read_only_root_filesystem' "$runtime_file")" != true ]] || runtime_args+=(--read-only)
    [[ "$(jq -r '.security.no_new_privileges' "$runtime_file")" != true ]] || runtime_args+=(--security-opt no-new-privileges)

    local -a entries=()
    local entry name
    mapfile -d '' -t entries < <(jq -j '.environment | to_entries[] | (.key + "=" + .value), "\u0000"' "$runtime_file")
    for entry in "${entries[@]}"; do
        name=${entry%%=*}
        [[ "$name" == HOSTNAME || "$name" == RUN_COMMAND || "$name" == MESH_CONNECT_HOST || "$name" == JAVA_TOOL_OPTIONS ]] && continue
        runtime_args+=(--env "$entry")
    done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.security.capability_add[]? | ., "\u0000"' "$runtime_file")
    for entry in "${entries[@]}"; do runtime_args+=(--cap-add "$entry"); done
    entries=()
    mapfile -d '' -t entries < <(jq -j '.security.capability_drop[]? | ., "\u0000"' "$runtime_file")
    for entry in "${entries[@]}"; do runtime_args+=(--cap-drop "$entry"); done

    local source destination writable projection
    while IFS= read -r -d '' source &&
        IFS= read -r -d '' destination &&
        IFS= read -r -d '' writable &&
        IFS= read -r -d '' projection; do
        resolve_snapshotted_source_mount "$source" "$destination" "$writable" "$projection"
        runtime_args+=(--volume "${prepared_mount_source}:${destination}:$([[ "$prepared_mount_writable" == true ]] && printf rw || printf ro)")
    done < <(jq -j '.mounts[]? | (.source // ""), "\u0000", .path, "\u0000", (.writable | tostring), "\u0000", .projection, "\u0000"' "$runtime_file")
    append_source_runtime_output_args

    mapfile -d '' -t entries < <(jq -j '.pod_command[]? | ., "\u0000"' "$runtime_file")
    if ((${#entries[@]} > 0)); then
        runtime_args+=(--entrypoint "${entries[0]}")
        ((${#entries[@]} == 1)) || runtime_command+=("${entries[@]:1}")
        local -a arguments=()
        if jq -e '.pod_args != null' "$runtime_file" >/dev/null; then
            mapfile -d '' -t arguments < <(jq -j '.pod_args[]? | ., "\u0000"' "$runtime_file")
        else
            mapfile -d '' -t arguments < <(jq -j '.image_command[]? | ., "\u0000"' "$runtime_file")
        fi
        runtime_command+=("${arguments[@]}")
    elif jq -e '.pod_args != null' "$runtime_file" >/dev/null; then
        mapfile -d '' -t runtime_command < <(jq -j '.pod_args[]? | ., "\u0000"' "$runtime_file")
    fi
}
