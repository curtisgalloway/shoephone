#!/bin/sh
# SPDX-FileCopyrightText: 2026 Curtis Galloway
# SPDX-License-Identifier: Apache-2.0
#
# A stand-in for terraform in the executor's tests. It appends its argv
# ("arg:" lines) and its environment ("env:" lines) to the file named by
# FAKE_TERRAFORM_RECORD, writes a line to stderr, and emits canned output:
#
#   init   a line of plain text
#   plan   writes the -out= file and one -json line
#   show   the file named by FAKE_TERRAFORM_SHOW
#   apply  appends "planfile:<contents of its plan argument>" to the
#          record, then one -json line
#
# FAKE_TERRAFORM_FAIL=<subcommand> makes that subcommand print a -json
# diagnostic whose summary is FAKE_TERRAFORM_TEXT and exit 1. Its address is
# FAKE_TERRAFORM_ADDRESS, or null_resource.broken.
# FAKE_TERRAFORM_SLEEP=<subcommand> makes that subcommand sleep 30 s.
# Only absolute paths are used, because the executor passes no PATH.

rec="${FAKE_TERRAFORM_RECORD:?FAKE_TERRAFORM_RECORD is not set}"
{
    printf 'call\n'
    for a in "$@"; do
        printf 'arg:%s\n' "$a"
    done
    /usr/bin/env | /usr/bin/sed 's/^/env:/'
} >>"$rec"

sub=""
out=""
last=""
for a in "$@"; do
    case "$a" in
        -out=*) out="${a#-out=}" ;;
        -*) ;;
        *)
            if [ -z "$sub" ]; then
                sub="$a"
            else
                last="$a"
            fi
            ;;
    esac
done

printf 'fake-terraform stderr for %s\n' "$sub" >&2

if [ "${FAKE_TERRAFORM_SLEEP:-}" = "$sub" ]; then
    /bin/sleep 30
fi

if [ "${FAKE_TERRAFORM_FAIL:-}" = "$sub" ]; then
    printf '{"type":"diagnostic","diagnostic":{"severity":"error","summary":"%s","address":"%s"}}\n' "${FAKE_TERRAFORM_TEXT:-}" "${FAKE_TERRAFORM_ADDRESS:-null_resource.broken}"
    exit 1
fi

case "$sub" in
    init) printf 'Terraform has been successfully initialized!\n' ;;
    plan)
        printf 'fake plan %s\n' "${FAKE_TERRAFORM_PLAN_TAG:-}" >"$out"
        printf '{"type":"version","terraform":"fake"}\n'
        ;;
    show) /bin/cat "${FAKE_TERRAFORM_SHOW:?FAKE_TERRAFORM_SHOW is not set}" ;;
    apply)
        printf 'planfile:%s\n' "$(/bin/cat "$last")" >>"$rec"
        printf '{"type":"apply_complete"}\n'
        ;;
    *) exit 2 ;;
esac
