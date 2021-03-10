if get_option('install-tools')
    scripts = files(
        'nf.tree.metrics',
        'nfsock',
        'cn_metrics.py',
    )

    install_data(
        scripts,
        install_dir: get_option('prefix') / get_option('bindir')
    )
endif
