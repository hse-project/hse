# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

tests = {
    'help': {},
    'no-args': {},
    'unknown-arg': {},
    'unknown-command': {},
    'version': {},

    'kvdb/help': {},
    'kvdb/no-args': {},
    'kvdb/unknown-arg': {},
    'kvdb/unknown-command': {},
    'kvdb/compact/help': {},
    'kvdb/compact/home-dne': {},
    'kvdb/compact/no-args': {},
    'kvdb/compact/success': {},
    'kvdb/compact/unknown-arg': {},
    'kvdb/create/help': {},
    'kvdb/create/home-dne': {},
    'kvdb/create/no-args': {},
    'kvdb/create/success': {},
    'kvdb/create/unknown-arg': {},
    'kvdb/drop/help': {},
    'kvdb/drop/home-dne': {},
    'kvdb/drop/no-args': {},
    'kvdb/drop/success': {}, # This gets tested with every test, for completeness...
    'kvdb/drop/unknown-arg': {},
    'kvdb/info/help': {},
    'kvdb/info/home-dne': {},
    'kvdb/info/no-args': {},
    'kvdb/info/success': {},
    'kvdb/info/unknown-arg': {},

    'kvs/help': {},
    'kvs/no-args': {},
    'kvs/unknown-arg': {},
    'kvs/unknown-command': {},
    'kvs/create/help': {},
    'kvs/create/home-dne': {},
    'kvs/create/name-invalid-chars': {},
    'kvs/create/name-too-long': {},
    'kvs/create/no-args': {},
    'kvs/create/success': {},
    'kvs/create/unknown-arg': {},
    'kvs/drop/help': {},
    'kvs/drop/home-dne': {},
    'kvs/drop/name-invalid-chars': {},
    'kvs/drop/name-too-long': {},
    'kvs/drop/no-args': {},
    'kvs/drop/success': {},
    'kvs/drop/unknown-arg': {},

    'storage/help': {},
    'storage/no-args': {},
    'storage/unknown-command': {},
    'storage/unknown-arg': {},
    'storage/add/help': {},
    'storage/add/home-dne': {},
    'storage/add/no-args': {},
    'storage/add/success': {},
    'storage/add/unknown-arg': {},
    'storage/info/help': {},
    'storage/info/home-dne': {},
    'storage/info/no-args': {},
    'storage/info/success': {},
    'storage/info/unknown-arg': {},
    'storage/profile/help': {},
    'storage/profile/home-dne': {},
    'storage/profile/no-args': {},
    'storage/profile/success': {
        'enabled': not ci,
    },
    'storage/profile/unknown-arg': {},

    'utils/help': {},
    'utils/no-args': {},
    'utils/unknown-command': {},
    'utils/unknown-arg': {},
    'utils/strerror/help': {},
    'utils/strerror/no-args': {},
    'utils/strerror/success': {},
    'utils/strerror/unknown-arg': {},
}

foreach t, params : tests
    if not params.get('enabled', true)
        continue
    endif

    # Is the current test targeting the root CLI?
    if fs.parent(t) == '.'
        name = 'cli[@0@]'.format(fs.name(t))
    else
        name = 'cli-@0@[@1@]'.format('-'.join(fs.parent(t).split('/')), fs.name(t))
    endif

    test(
        name,
        bash,
        args: [
            meson.current_source_dir() / '@0@.sh'.format(t),
        ],
        workdir: fs.parent(meson.current_source_dir()),
        timeout: 300,
        depends: [
            hse_exe_symlink,
        ],
        suite: ['functional', 'cli']
    )
endforeach
