
# Search/replace for HSE_VERSION and any other variables
#
configure_file( hse.py.in hse.py @ONLY )

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/hse.py
    DESTINATION ${HSE_PYTHON_SOS_PLUGINS_DIR}
    COMPONENT runtime
    )
