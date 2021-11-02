if not get_option('tools').disabled()
    subdir('scripts')
endif

tool_targets = {}

tools = {
    'attack': {
        'sources': files(
            'attack/attack.c',
        ),
    },
    'boundcur': {
        'sources': files(
            'boundcur/boundcur.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'capput': {
        'sources': files(
            'capput/capput.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'cn_kbdump': {
        'sources': files(
            'cn_kbdump/cn_kbdump.c',
            'parm_groups.c',
        ),
    },
    'cn_metrics': {
        'sources': files(
            'cn_metrics/cn_metrics.c',
            'common.c',
            'parm_groups.c',
        ),
    },
    'cndb_log': {
        'sources': files(
            'cndb_log/cndb_log.c',
            'parm_groups.c',
        ),
    },
    'cndb_txn_inject': {
        'sources': files(
            'cndb_tests/cndb_txn_inject.c',
        ),
    },
    'cndb_simpledrop_inject': {
        'sources': files(
            'cndb_tests/cndb_simpledrop_inject.c',
        ),
    },
    'cndb_simpledrop_recovery_inject': {
        'sources': files(
            'cndb_tests/cndb_simpledrop_recovery_inject.c',
        ),
    },
    'ctxn_validation': {
        'sources': files(
            'ctxn_validation/ctxn_validation.c',
            'parm_groups.c',
        ),
    },
    'curcache': {
        'sources': files(
            'curcache/curcache.c',
            'parm_groups.c',
        ),
    },
    'deviceprofile': {
        'sources': files(
            'deviceprofile/deviceprofile.c',
            'deviceprofile/deviceprofile_app.c',
        ),
        'c_args': [
            '-DHDR_HISTOGRAM_C_FROM_SUBPROJECT=@0@'.format(get_variable('HdrHistogram_c_from_subproject', 0)),
        ],
        'dependencies': [
            HdrHistogram_c_dep,
        ],
    },
    'omf_encoder_perf': {
        'sources': files(
            'omf_encoder_perf/omf_encoder_perf.c',
        ),
    },
    'kmt': {
        'sources': files(
            'kmt/kmt.c',
            'parm_groups.c',
        ),
        'c_args': [
            '-DHDR_HISTOGRAM_C_FROM_SUBPROJECT=@0@'.format(get_variable('HdrHistogram_c_from_subproject', 0)),
        ],
        'dependencies': [
            HdrHistogram_c_dep,
            libmongoc_dep,
            libbson_dep,
        ],
    },
    'xkmt': {
        'sources': files(
            'kmt/kmt.c',
            'parm_groups.c',
        ),
        'c_args': [
            '-DHDR_HISTOGRAM_C_FROM_SUBPROJECT=@0@'.format(get_variable('HdrHistogram_c_from_subproject', 0)),
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
            'ksync/ksync.c',
            'parm_groups.c',
        ),
    },
    'kvck': {
        'sources': files(
            'kvck/kvck.c',
            'parm_groups.c',
        ),
    },
    'bnt': {
        'sources': files(
            'bnt/bnt.c',
            'parm_groups.c',
        ),
        'dependencies': [
            ncurses_dep,
        ]
    },
    'kvt': {
        'sources': files(
            'kvt/kvt.c',
            'parm_groups.c',
        ),
        'dependencies': [
            ncurses_dep,
        ]
    },
    'longtest': {
        'sources': files(
            'longtest/longtest.c',
            'longtest/rsgen.c',
            'parm_groups.c',
        ),
    },
    'mdcperf': {
        'sources': files(
            'mpool/mdc/mdcperf.c',
        ),
    },
    'mdctest': {
        'sources': files(
            'mpool/mdc/mdctest.c',
        ),
    },
    'mdc_tool': {
        'sources': files(
            'mpool/mdc/mdc_tool.c',
        ),
    },
    'mpiotest': {
        'sources': files(
            'mpool/mblock/mpiotest.c',
        ),
    },
    'multicursor': {
        'sources': files(
            'multicursor/multicursor.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'pfx_probe': {
        'sources': files(
            'pfx_probe/pfx_probe.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
        'c_args': [
            '-DHSE_EXPERIMENTAL',
        ],
    },
    'pgd': {
        'sources': files(
            'pgd/pgd.c',
            'common.c',
            'parm_groups.c',
        ),
    },
    'pscan': {
        'sources': files(
            'pscan/pscan.c',
            'common.c',
            'parm_groups.c',
        ),
    },
    'ptree-overload': {
        'sources': files(
            'ptree-overload/ptree-overload.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'put_flush': {
        'sources': files(
            'put_flush/put_flush.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'put_txget': {
        'sources': files(
            'put_txget/put_txget.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'putbin': {
        'sources': files(
            'putbin/putbin.c',
            'common.c',
            'parm_groups.c',
        ),
    },
    'putgetdel': {
        'sources': files(
            'putgetdel/putgetdel.c',
            'key_generation.c',
            'parm_groups.c',
        ),
    },
    'range_read': {
        'sources': files(
            'range_read/range_read.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'simple_client': {
        'sources': files(
            'simple_client/simple_client.c',
            'parm_groups.c',
        ),
    },
    'throttle': {
        'sources': files(
            'throttle/throttle.c',
            'key_generation.c',
            'parm_groups.c',
        ),
    },
    'txn_thrash': {
        'sources': files(
            'txn_thrash/txn_thrash.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        ),
    },
    'txput_flush': {
        'sources': files(
            'txput_flush/txput_flush.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c',
        )
    },
    'waltest': {
        'sources': files(
            'waltest/waltest.c',
            'key_generation.c',
            'parm_groups.c',
        ),
    },
    'wbtsize': {
        'sources': files(
            'wbtsize/wbtsize.c',
            'parm_groups.c',
        ),
    },
    'wscan': {
        'sources': files(
            'wscan/wscan.c',
            'common.c',
            'parm_groups.c',
        ),
    },
}

foreach t, params : tools
    if not get_option('tools').disabled()
        target = executable(
            t,
            params['sources'],
            c_args: params.get('c_args', []),
            include_directories: [
                component_root_includes,
                hse_include_directories,
                tools_includes,
                params.get('include_directories', []),
            ],
            dependencies: [
                hse_internal_dep,
                hse_dependencies,
                libhse_cli_dep,
                params.get('dependencies', [])
            ],
            install: true,
            install_rpath: rpath,
            gnu_symbol_visibility: 'hidden',
        )

        tool_targets += { t: target }
    else
        tool_targets += { t: disabler() }
    endif
endforeach

executable_paths += meson.current_build_dir()
