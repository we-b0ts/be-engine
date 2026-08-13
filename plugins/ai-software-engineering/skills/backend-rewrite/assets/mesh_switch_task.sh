#!/bin/sh
set -u

trap 'exit 0' TERM INT

last_report=
while :; do
    report=
    while IFS= read -r mesh_command; do
        [ -n "$mesh_command" ] || continue
        response=$(printf '%s\r\n' "$mesh_command" | nc -w 1 127.0.0.1 880 2>&1)
        status=$?
        report="${report}${mesh_command}: exit=${status}"
        if [ -n "$response" ]; then
            report="${report}; response=${response}"
        fi
        report="${report}
"
    done <<'COMMANDS'
on resource mesh.switcher
off resource kv.mesh.auto.degrade.switcher
off resource mc.mesh.auto.degrade.switcher
off resource redis.mesh.auto.degrade.switcher
off resource mcq.mesh.auto.degrade.switcher
off resource uuid.mesh.auto.degrade.switcher
off resource vector.mesh.auto.degrade.switcher
off resource kv.mesh.exception.toTcp.switcher
off resource mc.mesh.exception.toTcp.switcher
off resource redis.mesh.exception.toTcp.switcher
off resource mcq.mesh.exception.toTcp.switcher
off resource uuid.mesh.exception.toTcp.switcher
off resource vector.mesh.exception.toTcp.switcher
COMMANDS

    if [ "$report" != "$last_report" ]; then
        printf 'mesh switch loop state changed:\n%s' "$report" >&2
        last_report=$report
    fi
    sleep 3
done
