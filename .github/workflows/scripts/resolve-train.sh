#!/usr/bin/env bash

######################################################################
# resolve a branch or train name to its .github/trains.json entry
#
# resolve-train.sh branch BRANCH   the pairing for a branch, if paired
# resolve-train.sh train TRAIN     the pairing for a named train
# resolve-train.sh default         the pairing for default_train
#
# Prints the matching trains[] entry as one line of JSON.  Set
# TRAINS_JSON to read a config from somewhere other than the checkout
# (kernel-watch.yml resolves against a copy fetched from the branch it
# is about to dispatch).
#
# Exit status:
#   0  an entry was printed
#   3  the config is valid but nothing matches
#   1  the config is missing or unusable (reason on stderr)
#
# Every lookup validates the whole file, so a bad edit is reported
# where it is made rather than six hours later as a "null" in a
# download URL or as two branches fighting over one release.
######################################################################

set -eu

CONFIG="${TRAINS_JSON:-.github/trains.json}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

usage() {
  echo "usage: resolve-train.sh branch BRANCH | train TRAIN | default" >&2
  exit 1
}

[ $# -ge 1 ] || usage

[ -f "$CONFIG" ] || die "$CONFIG is missing on this branch"
jq -e . "$CONFIG" > /dev/null 2>&1 || die "$CONFIG is not valid JSON"

jq -e '(.trains | type) == "array" and (.trains | length) > 0' \
  "$CONFIG" > /dev/null || die "$CONFIG has no trains[] entries"

# The shapes consumers depend on.  kernel_repo and kernel_tag end up in
# download URLs and on a command line, and train ends up in a release
# tag, so keep them to characters that cannot shift an argument or
# reach a shell.
malformed=$(jq -r '
  def ok($re): type == "string" and test($re);
  [ .trains[]
    | select(((.train       | ok("^[A-Za-z0-9._-]+$"))                and
              (.branch      | ok("^[A-Za-z0-9._/-]+$"))               and
              (.kernel_repo | ok("^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")) and
              (.kernel_tag  | ok("^[A-Za-z0-9._-]+$"))) | not)
    | tojson ]
  | join(", ")' "$CONFIG")
[ -z "$malformed" ] || die "$CONFIG has entries with a missing or" \
  "malformed train/branch/kernel_repo/kernel_tag: $malformed"

duplicated=$(jq -r '
  [ (.trains | group_by(.train)[]  | select(length > 1)
      | "train \(.[0].train)"),
    (.trains | group_by(.branch)[] | select(length > 1)
      | "branch \(.[0].branch)") ]
  | join(", ")' "$CONFIG")
[ -z "$duplicated" ] || die "$CONFIG lists $duplicated more than once;" \
  "two builds would fight over one release"

jq -e '.default_train as $t | any(.trains[]; .train == $t)' \
  "$CONFIG" > /dev/null \
  || die "$CONFIG default_train does not name a trains[] entry"

case "$1" in
  branch)
    [ $# -eq 2 ] || usage
    key="$2"
    field=branch
    ;;
  train)
    [ $# -eq 2 ] || usage
    key="$2"
    field=train
    ;;
  default)
    [ $# -eq 1 ] || usage
    key=$(jq -r '.default_train' "$CONFIG")
    field=train
    ;;
  *)
    usage
    ;;
esac

# The config is known good by now, so jq only fails here on a bug in
# this script; no match leaves entry empty rather than failing.
entry=$(jq -c --arg key "$key" --arg field "$field" \
  'first(.trains[] | select(.[$field] == $key)) // empty' "$CONFIG")
[ -n "$entry" ] || exit 3

printf '%s\n' "$entry"
