#!/bin/sh
# Merge new variables from .env.example into .env after a git pull.
#
# Appends any VAR=value line that .env.example has and .env lacks; existing
# lines in .env are never modified, so your customizations are safe.
# Idempotent -- run it as often as you like. .env is backed up to .env.bak
# before anything is added.
#
# Optional variables that ship commented out in .env.example (e.g.
# #FREERADIUS_IMAGE=...) are not copied -- enable those by hand.

set -eu
cd "$(dirname "$0")"

if [ ! -f .env ]; then
	echo "No .env found -- for a first-time setup run: cp .env.example .env" >&2
	exit 1
fi

missing=$(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' .env.example | while IFS= read -r line; do
	var=${line%%=*}
	grep -q "^${var}=" .env || printf '%s\n' "$line"
done)

if [ -z "$missing" ]; then
	echo ".env already has every variable in .env.example -- nothing to do."
	exit 0
fi

cp .env .env.bak
printf '%s\n' "$missing" >> .env

echo "Backed up .env to .env.bak and appended:"
printf '%s\n' "$missing" | sed 's/^/  /'
echo
echo "Each variable is documented in .env.example -- review the values you"
echo "just inherited (some are placeholders), then apply with:"
echo "  docker compose up -d --build --force-recreate"
