configs = files(
    'mongodb_imp.json',
    'mongodb_kmt.json',
    'mongodb_sysbench.json',
    'mongodb_ycsb_mclass_abcdef_load.json',
    'mongodb_ycsb_mclass_abcdef_run.json',
    'mongodb_ycsb.json',
    'native_kmt.json',
    'native_ycsb_abcdf_load.json',
    'native_ycsb_abcdf_run.json',
    'native_ycsb_e_load.json',
    'native_ycsb_e_run.json',
    'native_ycsb_mclass_abcdf_load.json',
    'native_ycsb_mclass_abcdf_run.json',
    'native_ycsb_mclass_e_load.json',
    'native_ycsb_mclass_e_run.json',
)

if get_option('install-configs')
    install_data(
        configs,
        install_dir: get_option('sysconfdir') / meson.project_name(),
    )
endif
