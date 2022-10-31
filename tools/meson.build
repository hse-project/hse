openapi_h = custom_target(
    'openapi.h',
    input: meson.project_source_root() / 'docs/openapi.json',
    output: 'openapi.h',
    command: [
        includeify,
        '-n',
        'openapi_json',
        '@INPUT@',
        '@OUTPUT@',
    ]
)

tool_targets = {}

tools = {
    'attack': {
        'dependencies': [hse_internal_dep],
        'sources': files('attack/attack.c'),
    },
    'boundcur': {
        'dependencies': [hse_internal_dep],
        'sources': files(
            'boundcur/boundcur.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c'
        ),
    },
    'capput': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'capput/capput.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c'
        ),
    },
    'cn_metrics': {
        'dependencies': [hse_internal_dep],
        'sources': files(
            'cn_metrics/cn_metrics.c',
            'common.c',
            'parm_groups.c'
        ),
    },
    'cndump': {
        'dependencies': [hse_internal_dep],
        'sources': files(
            'cndump/cndb_dump.c',
            'cndump/cndb_reader.c',
            'cndump/cndb_record.c',
            'cndump/cndump.c',
            'cndump/fatal.c',
            'cndump/kvset_dump.c',
        ),
    },
    'ctxn_validation': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'ctxn_validation/ctxn_validation.c',
            'parm_groups.c'
        ),
    },
    'curcache': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files('curcache/curcache.c', 'parm_groups.c'),
    },
    'hsettp': {
        'dependencies': [
            cc.find_library('dl'),
            cjson_dep,
            cjson_utils_dep,
            hse_error_dep,
            libbsd_dep,
            libhse_cli_dep,
	    hse_pidfile_dep,
            threads_dep,
        ],
        'export_dynamic': true,
        'sources': [
            openapi_h,
            files(
                'hsettp/buffer.c',
                'hsettp/format.c',
                'hsettp/hsettp.c',
                'hsettp/kvs-cn-tree-get.c',
                'hsettp/options_map.c',
                'hsettp/utils.c'
            ),
        ],
    },
    'omf_encoder_perf': {
        'dependencies': [hse_internal_dep],
        'sources': files('omf_encoder_perf/omf_encoder_perf.c'),
    },
    'kmt': {
        'dependencies': [
            HdrHistogram_c_dep,
            hse_internal_dep,
            libmongoc_dep,
            libbson_dep,
            threads_dep,
        ],
        'sources': files('kmt/kmt.c', 'parm_groups.c'),
    },
    'xkmt': {
        'c_args': [
            '-DXKMT',
        ],
        'dependencies': [
            HdrHistogram_c_dep,
            hse_internal_dep,
            libmongoc_dep,
            libbson_dep,
            threads_dep,
        ],
        'sources': files('kmt/kmt.c', 'parm_groups.c'),
    },
    'ksync': {
        'dependencies': [hse_internal_dep],
        'sources': files(
            'ksync/ksync.c',
            'parm_groups.c'
        ),
    },
    'bnt': {
        'dependencies': [
            hse_internal_dep,
            ncurses_dep,
            threads_dep,
        ],
        'sources': files('bnt/bnt.c', 'parm_groups.c'),
    },
    'kvt': {
        'dependencies': [
            hse_internal_dep,
            ncurses_dep,
            threads_dep,
        ],
        'sources': files('kvt/kvt.c', 'parm_groups.c'),
    },
    'longtest': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'longtest/longtest.c',
            'longtest/rsgen.c',
            'parm_groups.c'
        ),
    },
    'mdcperf': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files('mpool/mdc/mdcperf.c'),
    },
    'mdctest': {
        'dependencies': [hse_internal_dep],
        'sources': files('mpool/mdc/mdctest.c'),
    },
    'mdc_tool': {
        'dependencies': [hse_internal_dep],
        'sources': files('mpool/mdc/mdc_tool.c'),
    },
    'mpiotest': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files('mpool/mblock/mpiotest.c'),
    },
    'multicursor': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'multicursor/multicursor.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c'
        ),
    },
    'pfx_probe': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'pfx_probe/pfx_probe.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c'
        ),
    },
    'pgd': {
        'dependencies': [hse_internal_dep],
        'sources': files(
            'pgd/pgd.c',
            'common.c',
            'parm_groups.c'
        ),
    },
    'pscan': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'pscan/pscan.c',
            'common.c',
            'parm_groups.c'
        ),
    },
    'ptree-overload': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'ptree-overload/ptree-overload.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c'
        ),
    },
    'put_flush': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'put_flush/put_flush.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c'
        ),
    },
    'put_txget': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'put_txget/put_txget.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c'
        ),
    },
    'putbin': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'putbin/putbin.c',
            'common.c',
            'parm_groups.c'
        ),
    },
    'putgetdel': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'putgetdel/putgetdel.c',
            'key_generation.c',
            'parm_groups.c'
        ),
    },
    'range_read': {
        'dependencies': [
            hse_internal_dep,
            HdrHistogram_c_dep,
            threads_dep,
        ],
        'sources': files(
            'range_read/range_read.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c'
        ),
    },
    'simple_client': {
        'dependencies': [hse_internal_dep],
        'sources': files(
            'simple_client/simple_client.c',
            'parm_groups.c'
        ),
    },
    'throttle': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'throttle/throttle.c',
            'key_generation.c',
            'parm_groups.c'
        ),
    },
    'txn_thrash': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'txn_thrash/txn_thrash.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c'
        ),
    },
    'txput_flush': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'txput_flush/txput_flush.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c'
        )
    },
    'upsert': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'upsert/upsert.c',
            'common.c',
            'kvs_helper.c',
            'parm_groups.c'
        ),
    },
    'waltest': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'waltest/waltest.c',
            'key_generation.c',
            'parm_groups.c'
        ),
    },
    'wscan': {
        'dependencies': [
            hse_internal_dep,
            threads_dep,
        ],
        'sources': files(
            'wscan/wscan.c',
            'common.c',
            'parm_groups.c'
        ),
    },
}

foreach t, params : tools
    if get_option('tools').allowed()
        target = executable(
            t,
            params['sources'],
            c_args: params.get('c_args', []),
            include_directories: [
                component_root_includes,
                tools_includes,
                params.get('include_directories', []),
            ],
            dependencies: [
                libhse_cli_dep,
                params.get('dependencies', [])
            ],
            install: true,
            install_rpath: rpath,
            export_dynamic: params.get('export_dynamic', false),
            gnu_symbol_visibility: 'hidden'
        )

        tool_targets += { t: target }
    else
        tool_targets += { t: disabler() }
    endif
endforeach

executable_paths += meson.current_build_dir()
