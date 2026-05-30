#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 FSKY <development@fsky.io>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eu

# Example gibcert deploy hook for SSH hosts using rsync.
# Configure with:
#   GIBCERT_DEPLOY_HOSTS="web1 web2"
#   GIBCERT_DEPLOY_REMOTE_DIR=/etc/nginx/tls/example.com
# Optional:
#   GIBCERT_DEPLOY_RELOAD="systemctl reload nginx"
#   GIBCERT_DEPLOY_SSH=/path/to/ssh
#   GIBCERT_DEPLOY_RSYNC=/path/to/rsync

ssh_cmd=${GIBCERT_DEPLOY_SSH:-ssh}
rsync_cmd=${GIBCERT_DEPLOY_RSYNC:-rsync}

if [ "${GIBCERT_DEPLOY_HOSTS:-}" = "" ]; then
	echo "GIBCERT_DEPLOY_HOSTS is required" >&2
	exit 2
fi
if [ "${GIBCERT_DEPLOY_REMOTE_DIR:-}" = "" ]; then
	echo "GIBCERT_DEPLOY_REMOTE_DIR is required" >&2
	exit 2
fi

quote() {
	printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

add_file() {
	kind=$1
	src=$2
	name=$3
	if [ "$src" != "" ] && [ -f "$src" ]; then
		files="${files}${kind}|${src}|${name}
"
		names="${names} ${name}"
	fi
}

files=
names=
add_file cert "${GIBCERT_CERT_PATH:-}" cert.pem
add_file chain "${GIBCERT_CHAIN_PATH:-}" chain.pem
add_file fullchain "${GIBCERT_FULLCHAIN_PATH:-}" fullchain.pem
add_file key "${GIBCERT_KEY_PATH:-}" privkey.pem
add_file cert-der "${GIBCERT_CERT_DER_PATH:-}" cert.der
add_file key-der "${GIBCERT_KEY_DER_PATH:-}" privkey.der

if [ "$files" = "" ]; then
	echo "no gibcert deploy paths were set" >&2
	exit 2
fi

remote_dir=${GIBCERT_DEPLOY_REMOTE_DIR%/}
remote_dir_q=$(quote "$remote_dir")
reload=${GIBCERT_DEPLOY_RELOAD:-}

for host in $GIBCERT_DEPLOY_HOSTS; do
	echo "ssh-rsync: preparing ${host}:${remote_dir}"
	tmpdir=$("$ssh_cmd" "$host" "set -eu; install -d ${remote_dir_q}; mktemp -d ${remote_dir_q}/.gibcert.XXXXXX")

	cleanup_remote() {
		"$ssh_cmd" "$host" "rm -rf $(quote "$tmpdir")" >/dev/null 2>&1 || true
	}

	for name in $names; do
		src=$(printf '%s' "$files" | awk -F '|' -v want="$name" '$3 == want { print $2; exit }')
		kind=$(printf '%s' "$files" | awk -F '|' -v want="$name" '$3 == want { print $1; exit }')
		echo "ssh-rsync: copy ${kind} to ${host}:${remote_dir}/${name}"
		if ! "$rsync_cmd" -pt -- "$src" "${host}:${tmpdir}/${name}"; then
			cleanup_remote
			exit 1
		fi
	done

	move_script="set -eu;"
	for name in $names; do
		move_script="${move_script} mv -f $(quote "$tmpdir/$name") $(quote "$remote_dir/$name");"
	done
	move_script="${move_script} rmdir $(quote "$tmpdir");"
	if [ "$reload" != "" ]; then
		move_script="${move_script} ${reload};"
	fi

	if ! "$ssh_cmd" "$host" "$move_script"; then
		cleanup_remote
		exit 1
	fi
done
