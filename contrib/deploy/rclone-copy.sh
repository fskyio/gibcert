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

# Example gibcert deploy hook for rclone destinations.
# Configure with:
#   GIBCERT_RCLONE_DESTS="remote1:/path remote2:/path"
# Optional:
#   GIBCERT_RCLONE=/path/to/rclone

rclone_cmd=${GIBCERT_RCLONE:-rclone}

if [ "${GIBCERT_RCLONE_DESTS:-}" = "" ]; then
	echo "GIBCERT_RCLONE_DESTS is required" >&2
	exit 2
fi

add_file() {
	kind=$1
	src=$2
	name=$3
	if [ "$src" != "" ] && [ -f "$src" ]; then
		files="${files}${kind}|${src}|${name}
"
	fi
}

trim_slash() {
	path=$1
	while [ "${path%/}" != "$path" ]; do
		path=${path%/}
	done
	printf '%s\n' "$path"
}

files=
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

for dest in $GIBCERT_RCLONE_DESTS; do
	dest=$(trim_slash "$dest")
	printf '%s' "$files" | while IFS='|' read -r kind src name; do
		[ "$kind" != "" ] || continue
		tmp="${dest}/.gibcert-${GIBCERT_CERT:-cert}-$$-${name}"
		final="${dest}/${name}"
		echo "rclone: copy ${kind} to ${final}"
		"$rclone_cmd" copyto "$src" "$tmp"
		"$rclone_cmd" moveto "$tmp" "$final"
	done
done
