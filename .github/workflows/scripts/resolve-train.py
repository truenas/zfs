#!/usr/bin/env python3

"""
Resolve a branch or train name to its .github/trains.json entry.

resolve-train.py branch BRANCH   the pairing for a branch, if paired
resolve-train.py train TRAIN     the pairing for a named train
resolve-train.py default         the pairing for default_train

Prints the matching trains[] entry as one line of JSON.  Set
TRAINS_JSON to read a config from somewhere other than the checkout
(kernel-watch.yml resolves against a copy fetched from the branch it
is about to dispatch).

Exit status:
  0  an entry was printed
  3  the config is valid but nothing matches
  1  the config is missing or unusable (reason on stderr)

Every lookup validates the whole file, so a bad edit is reported where
it is made rather than six hours later as a "null" in a download URL
or as two branches fighting over one release.
"""

import json
import os
import re
import sys
from collections import Counter

# Field names in .github/trains.json.
TRAINS = 'trains'
DEFAULT_TRAIN = 'default_train'
TRAIN = 'train'
BRANCH = 'branch'
KERNEL_REPO = 'kernel_repo'
KERNEL_TAG = 'kernel_tag'

# The shapes consumers depend on.  kernel_repo and kernel_tag end up in
# download URLs and on a command line, and train ends up in a release
# tag, so keep them to characters that cannot shift an argument or
# reach a shell.
FIELDS = {
    TRAIN: r'[A-Za-z0-9._-]+',
    BRANCH: r'[A-Za-z0-9._/-]+',
    KERNEL_REPO: r'[A-Za-z0-9._-]+/[A-Za-z0-9._-]+',
    KERNEL_TAG: r'[A-Za-z0-9._-]+',
}

# An entry is looked up by one of these fields, so the lookups are
# named after them; DEFAULT takes its key from default_train instead.
LOOKUPS = (BRANCH, TRAIN)
DEFAULT = 'default'

# The config is fine, it just has nothing to say about what was asked.
NO_MATCH = 3


def die(*message):
    print('ERROR:', *message, file=sys.stderr)
    sys.exit(1)


def usage():
    print(f'usage: resolve-train.py {BRANCH} BRANCH | {TRAIN} TRAIN'
          f' | {DEFAULT}', file=sys.stderr)
    sys.exit(1)


def load(config):
    """Read the config, validating everything consumers depend on."""
    try:
        with open(config) as f:
            doc = json.load(f)
    except FileNotFoundError:
        die(f'{config} is missing on this branch')
    except json.JSONDecodeError as error:
        die(f'{config} is not valid JSON: {error}')
    except OSError as error:
        die(f'{config} is unreadable: {error.strerror}')

    trains = doc.get(TRAINS) if isinstance(doc, dict) else None
    if not isinstance(trains, list) or not trains:
        die(f'{config} has no {TRAINS}[] entries')

    malformed = []
    for index, entry in enumerate(trains):
        if not isinstance(entry, dict):
            malformed.append(f'{TRAINS}[{index}] is not an object')
            continue
        for field, pattern in FIELDS.items():
            value = entry.get(field)
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                malformed.append(
                    f'{TRAINS}[{index}] {field}={json.dumps(value)}')
    if malformed:
        die(f'{config} has entries with a missing or malformed',
            f'{"/".join(FIELDS)}:', '; '.join(malformed))

    duplicated = [f'{field} {value}'
                  for field in LOOKUPS
                  for value, count in Counter(e[field] for e in trains).items()
                  if count > 1]
    if duplicated:
        die(f'{config} lists {", ".join(duplicated)} more than once;',
            'two builds would fight over one release')

    default_train = doc.get(DEFAULT_TRAIN)
    if not any(entry[TRAIN] == default_train for entry in trains):
        die(f'{config} {DEFAULT_TRAIN} does not name a {TRAINS}[] entry')

    return doc


def main(argv):
    if not argv:
        usage()

    lookup = argv[0]
    if lookup in LOOKUPS and len(argv) == 2:
        field = lookup
    elif lookup == DEFAULT and len(argv) == 1:
        field = TRAIN
    else:
        usage()

    doc = load(os.environ.get('TRAINS_JSON') or '.github/trains.json')
    key = doc[DEFAULT_TRAIN] if lookup == DEFAULT else argv[1]

    for entry in doc[TRAINS]:
        if entry[field] == key:
            print(json.dumps(entry, separators=(',', ':')))
            return 0
    return NO_MATCH


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
