mpool_sources = files(
    'io_sync.c',
    'omf.c',
    'mpool.c',
    'mclass.c',
    'mblock.c',
    'mcache.c',
    'mblock_fset.c',
    'mblock_file.c',
    'mdc.c',
    'mdc_file.c',
    'mpool_file.c',
)

if libpmem_dep.found()
   mpool_sources += files('io_pmem.c')
endif

mpool_internal_includes = include_directories('.')
