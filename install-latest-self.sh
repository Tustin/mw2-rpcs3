#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target="$root/files/default_mp.self"
source_path=${1:-}

if [[ -z "$source_path" ]]; then
	for candidate in "$root"/files/default_mp*qos_v*.self; do
		[[ -f "$candidate" ]] || continue
		if [[ -z "$source_path" || "$candidate" -nt "$source_path" ]]; then
			source_path=$candidate
		fi
	done
fi

if [[ -z "$source_path" ]]; then
	printf 'no generated QoS SELF found under %s/files\n' "$root" >&2
	exit 1
fi

if [[ "$source_path" != /* ]]; then
	source_path="$root/$source_path"
fi

if [[ ! -f "$source_path" ]]; then
	printf 'SELF does not exist: %s\n' "$source_path" >&2
	exit 1
fi

if [[ "$source_path" == "$target" ]]; then
	printf 'SELF is already installed: %s\n' "$target"
	exit 0
fi

temporary="$target.tmp"
trap 'rm -f "$temporary"' EXIT
cp "$source_path" "$temporary"
mv -f "$temporary" "$target"
trap - EXIT

printf 'installed %s as %s\n' "$source_path" "$target"
sha256sum "$target"
