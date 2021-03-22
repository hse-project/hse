import argparse
import os
import sys


KVDB_NAME = None
KVS_NAME = "data"
LOG_DIR = None

MONITOR_DEVICES = []

REPORTS_MONGO_COLLECTION = "benchmarks"
REPORTS_MONGO_DATABASE = "hse_test"
REPORTS_MONGO_URI = None

REPORTS_MONGO_USERNAME = None
REPORTS_MONGO_PASSWORD = None


def __get_option(args, arg_name, env_name, default=None):
    value = getattr(args, arg_name)

    if not value:
        value = os.environ.get(env_name)
        if value:
            value = value.strip()

    if value is None:
        value = default

    return value


def __get_list_option(args, arg_name, env_name):
    value = getattr(args, arg_name)

    if not value:
        value = os.environ.get(env_name)
        if value:
            value = value.strip().split()

    return value


def is_device_monitoring_enabled():
    return MONITOR_DEVICES is not None and len(MONITOR_DEVICES) > 0


def is_reports_db_enabled():
    return bool(REPORTS_MONGO_URI)


def is_loaded():
    return bool(LOG_DIR)


def load():
    global KVDB_NAME
    global LOG_DIR

    global MONITOR_DEVICES

    global REPORTS_MONGO_COLLECTION
    global REPORTS_MONGO_DATABASE
    global REPORTS_MONGO_URI

    global REPORTS_MONGO_USERNAME
    global REPORTS_MONGO_PASSWORD

    parser = argparse.ArgumentParser()

    parser.add_argument("--kvdb", type=str)

    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--log-dir", type=str)

    parser.add_argument("--monitor-devices", nargs="+")

    parser.add_argument("--reports-mongo-collection", type=str)
    parser.add_argument("--reports-mongo-database", type=str)
    parser.add_argument("--reports-mongo-uri", type=str)

    parser.add_argument("--reports-mongo-username", type=str)
    parser.add_argument("--reports-mongo-password", type=str)

    parser.add_argument(
        "--show-env-help",
        help="Show the list of option environment variables",
        action="store_true",
    )

    args = parser.parse_args()

    if args.show_env_help:
        print("Environment variables:")
        print()
        print("HSE_TEST_BENCHMARK_LOG_DIR")
        print("HSE_TEST_KVDB")
        print()
        print("HSE_TEST_MONITOR_DEVICES              (list separated by spaces)")
        print()
        print("HSE_TEST_REPORTS_MONGO_COLLECTION")
        print("HSE_TEST_REPORTS_MONGO_DATABASE")
        print("HSE_TEST_REPORTS_MONGO_URI")
        print()
        print("HSE_TEST_REPORTS_MONGO_USERNAME")
        print("HSE_TEST_REPORTS_MONGO_PASSWORD")

        sys.exit(0)

    die = False

    KVDB_NAME = __get_option(args, "kvdb", "HSE_TEST_KVDB")
    if not KVDB_NAME:
        die = True
        print("KVDB name is required.")
        print(
            "Pass --kvdb on command line "
            "or set the HSE_TEST_KVDB environment variable."
        )
        print()

    LOG_DIR = __get_option(args, "log_dir", "HSE_TEST_BENCHMARK_LOG_DIR")
    if not LOG_DIR:
        if "MESON_BUILD_ROOT" in os.environ:
            LOG_DIR = os.path.join(os.environ["MESON_BUILD_ROOT"], "benchmark-logs")
        else:
            LOG_DIR = os.path.join(os.getcwd(), "benchmark-logs")

    if die:
        print("Quitting.")
        sys.exit(1)

    os.makedirs(LOG_DIR, exist_ok=True)

    MONITOR_DEVICES = __get_list_option(
        args, "monitor_devices", "HSE_TEST_MONITOR_DEVICES"
    )

    REPORTS_MONGO_COLLECTION = __get_option(
        args,
        "reports_mongo_collection",
        "HSE_TEST_REPORTS_MONGO_COLLECTION",
        default=REPORTS_MONGO_COLLECTION,
    )
    REPORTS_MONGO_DATABASE = __get_option(
        args,
        "reports_mongo_database",
        "HSE_TEST_REPORTS_MONGO_DATABASE",
        default=REPORTS_MONGO_DATABASE,
    )
    REPORTS_MONGO_URI = __get_option(
        args,
        "reports_mongo_uri",
        "HSE_TEST_REPORTS_MONGO_URI",
        default=REPORTS_MONGO_URI,
    )

    REPORTS_MONGO_USERNAME = __get_option(
        args, "reports_mongo_username", "HSE_TEST_REPORTS_MONGO_USERNAME"
    )
    REPORTS_MONGO_PASSWORD = __get_option(
        args, "reports_mongo_password", "HSE_TEST_REPORTS_MONGO_PASSWORD"
    )
