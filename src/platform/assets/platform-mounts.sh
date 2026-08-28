declare -A startup_mount_sources=()
declare -A startup_mount_writable=()
declare -A prepared_startup_roles=()
expected_startup_source=""
while IFS=$'\t' read -r source target writable; do
    [[ -n "$source" && -n "$target" ]] || continue
    [[ "$target" == /* && "$target" != / && "$target" != *//* && \
        "$target" != */./* && "$target" != */../* && \
        "$target" != */. && "$target" != */.. ]] || {
        printf 'error: invalid startup mount target %s\n' "$target" >&2
        exit 1
    }
    expected_startup_source="$startup_snapshot_mounts_root/${target#/}"
    [[ "$source" == "$expected_startup_source" ]] || {
        printf 'error: startup mount source for %s is outside the managed snapshot\n' \
            "$target" >&2
        exit 1
    }
    [[ "$writable" == true || "$writable" == false ]] || {
        printf 'error: startup mount %s has invalid writable mode %s\n' "$target" "$writable" >&2
        exit 1
    }
    [[ ! -v 'startup_mount_sources[$target]' ]] || {
        printf 'error: duplicate startup mount target %s\n' "$target" >&2
        exit 1
    }
    startup_mount_sources["$target"]=$source
    startup_mount_writable["$target"]=$writable
done <"$TRAFFIC_E2E_TARGET_STARTUP_MOUNTS_FILE"

mount_paths_overlap() {
    local left=$1
    local right=$2
    [[ "$left" == "$right" || "$left" == "$right/"* || "$right" == "$left/"* ]]
}

validate_container_mount_path() {
    local path=$1
    [[ "$path" == /* && "$path" != / && "$path" != *//* && \
        "$path" != */./* && "$path" != */../* && \
        "$path" != */. && "$path" != */.. && \
        "$path" != *$'\n'* && "$path" != *$'\r'* && "$path" != *$'\t'* ]]
}

runtime_output_ids=()
declare -A runtime_output_targets=()
declare -A runtime_output_ids_by_target=()
declare -A prepared_runtime_output_roles=()
declare -A seen_source_runtime_outputs=()
runtime_output_root_prepared=false
while IFS=$'\t' read -r output_id output_target; do
    [[ -n "$output_id" && -n "$output_target" ]] || continue
    [[ "$output_id" =~ ^[A-Za-z0-9._-]{1,64}$ && \
        "$output_id" != . && "$output_id" != .. ]] || {
        printf 'error: invalid runtime output id %s\n' "$output_id" >&2
        exit 1
    }
    validate_container_mount_path "$output_target" || {
        printf 'error: invalid runtime output path %s\n' "$output_target" >&2
        exit 1
    }
    [[ ! -v 'runtime_output_targets[$output_id]' ]] || {
        printf 'error: duplicate runtime output id %s\n' "$output_id" >&2
        exit 1
    }
    [[ ! -v 'runtime_output_ids_by_target[$output_target]' ]] || {
        printf 'error: duplicate runtime output path %s\n' "$output_target" >&2
        exit 1
    }
    runtime_output_ids+=("$output_id")
    runtime_output_targets["$output_id"]=$output_target
    runtime_output_ids_by_target["$output_target"]=$output_id
done <"$TRAFFIC_E2E_TARGET_RUNTIME_OUTPUTS_FILE"

prepare_runtime_outputs() {
    local role=$1
    [[ "$role" == source || "$role" == target ]] || {
        printf 'error: invalid runtime output role %s\n' "$role" >&2
        return 1
    }
    [[ -v 'prepared_runtime_output_roles[$role]' ]] && return 0
    if ((${#runtime_output_ids[@]} == 0)); then
        prepared_runtime_output_roles["$role"]=true
        return 0
    fi
    if ! "$runtime_output_root_prepared"; then
        [[ ! -e "$runtime_outputs_root" && ! -L "$runtime_outputs_root" ]] || {
            printf 'error: runtime output root already exists: %s\n' \
                "$runtime_outputs_root" >&2
            return 1
        }
        mkdir -p "$(dirname "$runtime_outputs_root")"
        mkdir "$runtime_outputs_root"
        chmod 0700 "$runtime_outputs_root"
        runtime_output_root_prepared=true
    fi
    local role_root="$runtime_outputs_root/$role"
    [[ ! -e "$role_root" ]] || {
        printf 'error: runtime output role root already exists: %s\n' "$role_root" >&2
        return 1
    }
    mkdir "$role_root"
    chmod 0700 "$role_root"
    docker run --rm --platform linux/amd64 --network none --user 0:0 \
        --entrypoint /bin/sh \
        --mount "type=bind,source=${role_root},target=/workspace/runtime-outputs" \
        "$anchor_image" -ec '
            owner=$1
            shift
            for id do
                mkdir "/workspace/runtime-outputs/$id"
                chown "$owner:998" "/workspace/runtime-outputs/$id"
                chmod 2770 "/workspace/runtime-outputs/$id"
            done
        ' sh "$runtime_uid" "${runtime_output_ids[@]}"
    prepared_runtime_output_roles["$role"]=true
}

append_source_runtime_output_args() {
    prepare_runtime_outputs source
    local output_id output_target
    for output_id in "${runtime_output_ids[@]}"; do
        output_target=${runtime_output_targets[$output_id]}
        if [[ ! -v 'seen_source_runtime_outputs[$output_target]' ]]; then
            runtime_args+=(--volume "$runtime_outputs_root/source/${output_id}:${output_target}:rw")
        fi
        printf 'source runtime output %s: %s -> %s\n' \
            "$output_id" "$output_target" \
            "$runtime_outputs_root/source/${output_id}" >&2
    done
}

ensure_platform_mount_root() {
    if [[ ! -d "$platform_mounts_root" ]]; then
        [[ ! -e "$platform_mounts_root" ]] || {
            printf 'error: platform runtime mount root is not a directory: %s\n' \
                "$platform_mounts_root" >&2
            return 1
        }
        mkdir "$platform_mounts_root"
        chmod 0700 "$platform_mounts_root"
    fi
}

ensure_role_mount_root() {
    local role=$1
    local role_root="$platform_mounts_root/$role"
    ensure_platform_mount_root
    if [[ ! -d "$role_root" ]]; then
        mkdir "$role_root"
        chmod 0700 "$role_root"
    fi
}

prepare_writable_startup_mounts() {
    local role=$1
    [[ -v 'prepared_startup_roles[$role]' ]] && return 0
    ensure_role_mount_root "$role"
    local -a relative_paths=()
    local target
    for target in "${!startup_mount_sources[@]}"; do
        [[ "${startup_mount_writable[$target]}" == true ]] || continue
        relative_paths+=("${target#/}")
    done
    if ((${#relative_paths[@]} > 0)); then
        docker run --rm --platform linux/amd64 --network none --user 0:0 \
            --entrypoint /bin/sh \
            --mount "type=bind,source=${startup_snapshot_mounts_root},target=/workspace/startup,readonly" \
            --mount "type=bind,source=${platform_mounts_root}/${role},target=/workspace/runtime" \
            "$anchor_image" -ec '
                source_root=$1
                runtime_root=$2
                shift 2
                for relative do
                    mkdir -p "$runtime_root/$(dirname "$relative")"
                    cp --archive --reflink=auto -- "$source_root/$relative" "$runtime_root/$relative"
                done
            ' sh /workspace/startup /workspace/runtime "${relative_paths[@]}"
    fi
    prepared_startup_roles["$role"]=true
}

resolve_startup_mount_source() {
    local role=$1
    local target=$2
    local writable=$3
    if [[ "$writable" == true ]]; then
        prepare_writable_startup_mounts "$role"
        prepared_mount_source="$platform_mounts_root/$role/${target#/}"
    else
        prepared_mount_source=${startup_mount_sources[$target]}
    fi
}

prepare_empty_runtime_mount() {
    local role=$1
    local destination=$2
    local relative=${destination#/}
    ensure_role_mount_root "$role"
    docker run --rm --platform linux/amd64 --network none --user 0:0 \
        --entrypoint /bin/sh \
        --mount "type=bind,source=${platform_mounts_root}/${role},target=/workspace/runtime" \
        "$anchor_image" -ec '
            target="/workspace/runtime/$1"
            mkdir -p "$target"
            chown 998:998 "$target"
            chmod 0775 "$target"
        ' sh "$relative"
    prepared_mount_source="$platform_mounts_root/$role/$relative"
}

resolve_recording_mount_source() {
    local destination=$1
    local writable=$2
    local original_source=$3
    local startup_target
    local runtime_output_target
    prepared_mount_writable=$writable
    if [[ -v 'runtime_output_ids_by_target[$destination]' ]]; then
        prepare_runtime_outputs source
        prepared_mount_source="$runtime_outputs_root/source/${runtime_output_ids_by_target[$destination]}"
        prepared_mount_writable=true
        seen_source_runtime_outputs["$destination"]=true
        return 0
    fi
    for runtime_output_target in "${runtime_output_targets[@]}"; do
        if mount_paths_overlap "$destination" "$runtime_output_target"; then
            printf 'error: source mount %s partially overlaps runtime output %s\n' \
                "$destination" "$runtime_output_target" >&2
            return 1
        fi
    done
    if [[ -v 'startup_mount_sources[$destination]' ]]; then
        [[ "$writable" == "${startup_mount_writable[$destination]}" ]] || {
            printf 'error: source mount %s is %s but the startup snapshot requires writable=%s; initialized startup inputs require administrator repair\n' \
                "$destination" "$writable" "${startup_mount_writable[$destination]}" >&2
            return 1
        }
        resolve_startup_mount_source source "$destination" "$writable"
        return 0
    fi
    for startup_target in "${!startup_mount_sources[@]}"; do
        if mount_paths_overlap "$destination" "$startup_target"; then
            printf 'error: source mount %s partially overlaps startup mount %s; configure an exact startup mount or remove the overlap\n' \
                "$destination" "$startup_target" >&2
            return 1
        fi
    done
    if [[ "$destination" == /data1/breeze/* || "$original_source" == /data1/breeze/* ]]; then
        prepared_mount_source=$original_source
    else
        prepare_empty_runtime_mount source "$destination"
    fi
}

remove_platform_mounts() {
    [[ -d "$platform_mounts_root" ]] || return 0
    if docker image inspect "$anchor_image" >/dev/null 2>&1; then
        docker run --rm --platform linux/amd64 --network none --user 0:0 \
            --entrypoint /bin/sh \
            --mount "type=bind,source=${platform_mounts_parent},target=/workspace/runtime" \
            "$anchor_image" -ec 'rm -rf -- "$1"' sh \
            "/workspace/runtime/${operation}-${token}"
    else
        remove_private_runtime_dir "$platform_mounts_root" "$platform_mounts_parent"
    fi
}
