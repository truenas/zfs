#!/usr/bin/env python3

"""
Fetch and verify debs from a rolling TrueNAS kernel release.

fetch-tn-kernel.py KERNEL_REPO KERNEL_TAG DIR PATTERN...

KERNEL_REPO: GitHub repository publishing the rolling kernel
             releases (e.g. truenas/linux)
KERNEL_TAG:  release tag to install the kernel from (e.g.
             master-nightly); the pairing lives in
             .github/trains.json
DIR:         directory to download into, created if needed
PATTERN:     shell patterns matched against the manifest's debs[].
             A pattern starting with '!' excludes, and exclusions
             win however the patterns are ordered.

Consumes the release the same way downstream consumers are meant to:
fetch manifest.json to learn the current kernel release and file
names, then verify the debs against SHA256SUMS.  Leaves manifest.json
in DIR for the caller to read .release and .commit from.

ci.yml (headers only, in a container) and qemu-tn-kernel-vm.sh (image
and headers, on the test VM) both consume releases this way; one copy
keeps the checksum verification identical on both paths.
"""

import fnmatch
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

# Files every kernel release publishes, and the manifest field naming
# the debs it carries.
MANIFEST = 'manifest.json'
SHA256SUMS = 'SHA256SUMS'
DEBS = 'debs'

# A pattern with this prefix excludes rather than includes.
EXCLUDE = '!'

# sha256sum marks binary-mode entries with a leading '*'.
BINARY_MODE = '*'

# The kernel image deb is ~100MB, so hash it as it arrives rather than
# holding it in memory.
CHUNK = 1024 * 1024

USER_AGENT = 'fetch-tn-kernel'


def die(*message):
    print('ERROR:', *message, file=sys.stderr)
    sys.exit(1)


def download(url, path, missing=None):
    """Stream url into path, returning its sha256 digest.

    Exits with `missing` if the release does not have the file at all,
    so a release that has not been published yet is reported as such
    rather than as a bare 404.
    """
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(request) as response:
            with open(path, 'wb') as out:
                while True:
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
                    out.write(chunk)
    except urllib.error.HTTPError as error:
        if error.code == 404 and missing:
            die(missing)
        die(f'{url}: HTTP {error.code} {error.reason}')
    except urllib.error.URLError as error:
        die(f'{url}: {error.reason}')
    return digest.hexdigest()


def read_json(path, url):
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as error:
        die(f'{url} is not valid JSON: {error}')


def read_sums(path):
    """Map file name to expected digest from a sha256sum -c style file."""
    sums = {}
    with open(path) as f:
        for line in f:
            fields = line.split(maxsplit=1)
            if len(fields) != 2:
                continue
            digest, name = fields
            sums[name.strip().removeprefix(BINARY_MODE)] = digest.lower()
    return sums


def select(debs, patterns):
    """Apply the include and exclude patterns to the manifest's debs[]."""
    includes = [p for p in patterns if not p.startswith(EXCLUDE)]
    excludes = [p.removeprefix(EXCLUDE) for p in patterns
                if p.startswith(EXCLUDE)]
    return [deb for deb in debs
            if any(fnmatch.fnmatchcase(deb, p) for p in includes)
            # Exclusions win however the patterns were ordered.
            and not any(fnmatch.fnmatchcase(deb, p) for p in excludes)]


def fetch(url, directory, patterns):
    os.makedirs(directory, exist_ok=True)

    manifest_url = f'{url}/{MANIFEST}'
    manifest_path = os.path.join(directory, MANIFEST)
    download(manifest_url, manifest_path,
             missing=f'no kernel release published at {url} yet')
    manifest = read_json(manifest_path, manifest_url)

    sums_path = os.path.join(directory, SHA256SUMS)
    download(f'{url}/{SHA256SUMS}', sums_path)
    sums = read_sums(sums_path)

    debs = manifest.get(DEBS) if isinstance(manifest, dict) else None
    if not isinstance(debs, list):
        die(f'{manifest_url} has no {DEBS}[]')

    wanted = select(debs, patterns)
    if not wanted:
        die(f'{manifest_url} lists no deb matching', ' '.join(patterns))

    # An unexpected rename in the release must not verify vacuously, so
    # prove SHA256SUMS covers every deb before downloading any of them.
    for deb in wanted:
        if deb not in sums:
            die(f'{deb} is not listed in {url}/{SHA256SUMS}')

    for deb in wanted:
        print(f'Downloading {deb}', file=sys.stderr)
        digest = download(f'{url}/{deb}', os.path.join(directory, deb))
        if digest != sums[deb]:
            die(f'{deb} does not match {url}/{SHA256SUMS}:',
                f'expected {sums[deb]}, got {digest}')
        print(f'{deb}: OK', file=sys.stderr)


def main(argv):
    if len(argv) < 4:
        print('usage: fetch-tn-kernel.py KERNEL_REPO KERNEL_TAG DIR'
              ' PATTERN...', file=sys.stderr)
        return 1

    repo, tag, directory = argv[:3]
    fetch(f'https://github.com/{repo}/releases/download/{tag}',
          directory, argv[3:])
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
