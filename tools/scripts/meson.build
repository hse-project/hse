if get_option('install-tools')
    scripts = files(
        'nf.tree.metrics',
    )

    install_data(
        scripts,
        install_dir: get_option('prefix') / get_option('bindir')
    )
endif
