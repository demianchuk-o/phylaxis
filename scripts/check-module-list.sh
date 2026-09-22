#!/bin/sh
# Refuse a commit whose crate module list and committed files disagree.
#
# WHY this exists: while a crate lands block by block, its `lib.rs` is the one file whose
# working-tree version is deliberately not the version to commit, and restoring the full copy
# after a commit — which you must, or the working tree stops building — is exactly what makes
# the next commit wrong. It happened twice on 2026-09-16, in both directions: modules
# committed without being declared, then modules declared that were not committed. The second
# left `HEAD` not compiling at all.
#
# It reads the index, never the working tree, so it sees what the commit will actually contain.
# It does not compile anything; it takes well under a second.
set -eu

status=0

note() {
	printf '%s\n' "$*" >&2
}

# Top-level `mod x;` declarations in a file held in the index. Inline `mod x { .. }` has no
# file behind it and is skipped by requiring the semicolon.
declared_modules() {
	git show ":$1" 2>/dev/null |
		grep -E '^[[:space:]]*(pub[[:space:]]+|pub\([a-z_:]+\)[[:space:]]+)?mod[[:space:]]+[a-z_0-9]+[[:space:]]*;' |
		sed -E 's/.*mod[[:space:]]+([a-z_0-9]+)[[:space:]]*;.*/\1/'
}

in_index() {
	git ls-files --error-unmatch --cached -- "$1" >/dev/null 2>&1
}

staged=$(git diff --cached --name-only --diff-filter=ACMR)
[ -n "$staged" ] || exit 0

crates=$(printf '%s\n' "$staged" |
	sed -n -E 's#^(crates/[a-z_0-9-]+)/src/.*#\1#p' |
	sort -u)

for crate in $crates; do
	lib="$crate/src/lib.rs"
	in_index "$lib" || continue
	modules=$(declared_modules "$lib")

	# Direction 1 — declared but not committed. This is what breaks the build of HEAD.
	for m in $modules; do
		if ! in_index "$crate/src/$m.rs" && ! in_index "$crate/src/$m/mod.rs"; then
			note "module list: $lib declares \`mod $m;\` but $crate/src/$m.rs is not in the commit"
			status=1
		fi
	done

	# Direction 2 — committed but not declared. Builds fine and ships dead files.
	for f in $(printf '%s\n' "$staged" | sed -n -E "s#^$crate/src/([a-z_0-9]+)\.rs\$#\1#p"); do
		case "$f" in
		lib | main) continue ;;
		esac
		printf '%s\n' "$modules" | grep -qx "$f" || {
			note "module list: $crate/src/$f.rs is in the commit but $lib does not declare \`mod $f;\`"
			status=1
		}
	done
done

if [ "$status" -ne 0 ]; then
	note ""
	note "Fix the staged lib.rs — not the working-tree one — and commit again."
	note "To check HEAD itself afterwards: git worktree add --detach <tmp> HEAD && cargo test"
fi

exit "$status"
