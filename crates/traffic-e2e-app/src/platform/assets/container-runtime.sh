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
        [[ "$name" == HOSTNAME || "$name" == RUN_COMMAND || "$name" == JAVA_TOOL_OPTIONS ]] && continue
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
