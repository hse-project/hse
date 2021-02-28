configs = files(
    'mongodb_imp.yml',
    'mongodb_kmt.yml',
    'mongodb_sysbench.yml',
    'mongodb_ycsb_mclass_abcdef_load.yml',
    'mongodb_ycsb_mclass_abcdef_run.yml',
    'mongodb_ycsb.yml',
    'native_kmt.yml',
    'native_ycsb_abcdf_load.yml',
    'native_ycsb_abcdf_run.yml',
    'native_ycsb_e_load.yml',
    'native_ycsb_e_run.yml',
    'native_ycsb_mclass_abcdf_load.yml',
    'native_ycsb_mclass_abcdf_run.yml',
    'native_ycsb_mclass_e_load.yml',
    'native_ycsb_mclass_e_run.yml',
)

if get_option('install-configs')
    install_data(
        configs,
        install_dir: get_option('sysconfdir') / meson.project_name(),
    )
endif
