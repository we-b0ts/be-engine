#!/usr/bin/env bash
set -Eeuo pipefail

send_command() {
    local command=$1
    printf '%s\r\n' "${command}" | nc -w 3 127.0.0.1 880
}

send_command "on resource mesh.switcher"
send_command "off resource kv.mesh.auto.degrade.switcher"
send_command "off resource mc.mesh.auto.degrade.switcher"
send_command "off resource redis.mesh.auto.degrade.switcher"
send_command "off resource mcq.mesh.auto.degrade.switcher"
send_command "off resource uuid.mesh.auto.degrade.switcher"
send_command "off resource vector.mesh.auto.degrade.switcher"

send_command "off resource kv.mesh.exception.toTcp.switcher"
send_command "off resource mc.mesh.exception.toTcp.switcher"
send_command "off resource redis.mesh.exception.toTcp.switcher"
send_command "off resource mcq.mesh.exception.toTcp.switcher"
send_command "off resource uuid.mesh.exception.toTcp.switcher"
send_command "off resource vector.mesh.exception.toTcp.switcher"
