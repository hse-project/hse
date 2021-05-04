subdir('3rdparty')
subdir('db_bench')
subdir('scripts')

tool_targets = {}

tools = {
    'attack': {
        'sources': files(
            'attack' / 'attack.c',
        ),
    },
    'boundcur': {
        'sources': files(
            'boundcur' / 'boundcur.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'capput': {
        'sources': files(
            'capput' / 'capput.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'cn_kbdump': {
        'sources': files(
            'cn_kbdump' / 'cn_kbdump.c',
            'parm_groups.c',
        ),
    },
    'cn_metrics': {
        'sources': files(
            'cn_metrics' / 'cn_metrics.c',
            'common.c',
            'parm_groups.c',
        ),
    },
    'cndb_log': {
        'sources': files(
            'cndb_log' / 'cndb_log.c',
            'parm_groups.c',
        ),
    },
    'ctxn_validation': {
        'sources': files(
            'ctxn_validation' / 'ctxn_validation.c',
            'parm_groups.c',
        ),
    },
    'curcache': {
        'sources': files(
            'curcache' / 'curcache.c',
            'parm_groups.c',
        ),
    },
    'deviceprofile': {
        'sources': files(
            'deviceprofile' / 'deviceprofile.c',
            'deviceprofile' / 'deviceprofile_app.c',
        ),
        'c_args': [
            '-DHDR_HISTOGRAM_C_FROM_SUBPROJECT=@0@'.format(HdrHistogram_c_from_subproject ? 1 : 0),
        ],
        'dependencies': [
            HdrHistogram_c_dep,
        ],
    },
    'omf_encoder_perf': {
        'sources': files(
            'omf_encoder_perf' / 'omf_encoder_perf.c',
        ),
    },
    'kmt': {
        'sources': files(
            'kmt' / 'kmt.c',
            '3rdparty' / 'src' / 'murmur3.c',
            'parm_groups.c',
        ),
        'c_args': [
            '-DHDR_HISTOGRAM_C_FROM_SUBPROJECT=@0@'.format(HdrHistogram_c_from_subproject ? 1 : 0),
        ],
        'dependencies': [
            HdrHistogram_c_dep,
            libmongoc_dep,
            libbson_dep,
        ],
    },
    'xkmt': {
        'sources': files(
            'kmt' / 'kmt.c',
            '3rdparty' / 'src' / 'murmur3.c',
            'parm_groups.c',
        ),
        'c_args': [
            '-DHDR_HISTOGRAM_C_FROM_SUBPROJECT=@0@'.format(HdrHistogram_c_from_subproject ? 1 : 0),
            '-DXKMT',
        ],
        'dependencies': [
            HdrHistogram_c_dep,
            libmongoc_dep,
            libbson_dep,
        ],
    },
    'ksync': {
        'sources': files(
            'ksync' / 'ksync.c',
            'parm_groups.c',
        ),
    },
    'kvck': {
        'sources': files(
            'kvck' / 'kvck.c',
            'parm_groups.c',
        ),
    },
    'bnt': {
        'sources': files(
            'bnt' / 'bnt.c',
            '3rdparty' / 'src' / 'murmur3.c',
            'parm_groups.c',
        ),
        'dependencies': [
            ncurses_dep,
        ]
    },
    'kvt': {
        'sources': files(
            'kvt' / 'kvt.c',
            '3rdparty' / 'src' / 'murmur3.c',
            'parm_groups.c',
        ),
        'dependencies': [
            ncurses_dep,
        ]
    },
    'longtest': {
        'sources': files(
            'longtest' / 'longtest.c',
            'longtest' / 'rsgen.c',
            'parm_groups.c',
        ),
    },
    'mdcperf': {
        'sources': files(
            'mpool' / 'mdc' / 'mdcperf.c',
        ),
    },
    'mdctest': {
        'sources': files(
            'mpool' / 'mdc' / 'mdctest.c',
        ),
    },
    'mpiotest': {
        'sources': files(
            'mpool' / 'mblock' / 'mpiotest.c',
        ),
    },
    'mpool_profile': {
        'sources': files(
            'mpool' / 'mblock' / 'mpool_profile.c',
        ),
    },
    'multicursor': {
        'sources': files(
            'multicursor' / 'multicursor.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'pfx_probe': {
        'sources': files(
            'pfx_probe' / 'pfx_probe.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        )
    },
    'pgd': {
        'sources': files(
            'pgd' / 'pgd.c',
            'common.c',
            'parm_groups.c',
        ),
    },
    'pscan': {
        'sources': files(
            'pscan' / 'pscan.c',
            'common.c',
            'parm_groups.c',
        ),
    },
    'ptree-overload': {
        'sources': files(
            'ptree-overload' / 'ptree-overload.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'put_flush': {
        'sources': files(
            'put_flush' / 'put_flush.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'put_txget': {
        'sources': files(
            'put_txget' / 'put_txget.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'putbin': {
        'sources': files(
            'putbin' / 'putbin.c',
            'common.c',
            'parm_groups.c',
        ),
    },
    'putgetdel': {
        'sources': files(
            'putgetdel' / 'putgetdel.c',
            'key_generation.c',
            'parm_groups.c',
        ),
    },
    'range_read': {
        'sources': files(
            'range_read' / 'range_read.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'simple_client': {
        'sources': files(
            'simple_client' / 'simple_client.c',
            'parm_groups.c',
        ),
    },
    'throttle': {
        'sources': files(
            'throttle' / 'throttle.c',
            'key_generation.c',
            'parm_groups.c',
        ),
    },
    'txn_thrash': {
        'sources': files(
            'txn_thrash' / 'txn_thrash.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'txput_flush': {
        'sources': files(
            'txput_flush' / 'txput_flush.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        )
    },
    'wbtsize': {
        'sources': files(
            'wbtsize' / 'wbtsize.c',
            'parm_groups.c',
        ),
    },
    'wscan': {
        'sources': files(
            'wscan' / 'wscan.c',
            'common.c',
            'parm_groups.c',
        ),
    },
}

foreach t, params : tools

    t_sources = params['sources']

    t_c_args = [
        '-D_GNU_SOURCE=1',
        '-DCOMPNAME="@0@"'.format(t),
    ]
    if 'c_args' in params
        t_c_args += params['c_args']
    endif

    t_include_directories = [
        component_root_includes,
        hse_include_directories,
        tools_includes,
        tools_third_party_includes
    ]
    if 'include_directories' in params
        t_include_directories += params['include_directories']
    endif

    t_dependencies = [
        hse_static_dep,
        hse_dependencies,
        libhse_cli_dep,
    ]
    if 'dependencies' in params
        t_dependencies += params['dependencies']
    endif

    target = executable(
        t,
        t_sources,
        c_args: t_c_args,
        include_directories: t_include_directories,
        dependencies: t_dependencies,
        install: get_option('install-tools'),
        install_rpath: exe_install_rpath,
        gnu_symbol_visibility: 'hidden',
    )

    tool_targets += { t: target }
endforeach

executable_paths += meson.current_build_dir()
