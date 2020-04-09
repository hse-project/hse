
FILE(GLOB CONFIG_FILES LIST_DIRECTORIES false *.yml)

INSTALL(
    FILES       ${CONFIG_FILES}
    DESTINATION /opt/hse/config
    COMPONENT   runtime
    )
