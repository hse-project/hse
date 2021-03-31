import argparse
import os
import sys
from pathlib import Path


# https://stackoverflow.com/a/55423170
AVAILABLE_CPUS = len(os.sched_getaffinity(0))

HSE_EXECUTABLE = "hse1"

KVDB_NAME = None
KVS_NAME = "data"
LOG_DIR = None

MONITOR_DEVICES = []

REPORTS_MONGO_COLLECTION = "benchmarks"
REPORTS_MONGO_DATABASE = "hse_test"
REPORTS_MONGO_URI = None

REPORTS_MONGO_USERNAME = None
REPORTS_MONGO_PASSWORD = None

YCSB_HOME = None


def __get_option(args, arg_name, env_name, default=None, type=None):
    value = getattr(args, arg_name)

    if not value:
        value = os.environ.get(env_name)
        if value:
            value = value.strip()

    if value is None:
        value = default

    if value is not None and type is not None:
        return type(value)
    else:
        return value


def __get_list_option(args, arg_name, env_name):
    value = getattr(args, arg_name)

    if not value:
        value = os.environ.get(env_name)
        if value:
            value = value.strip().split()

    return value


def check_ycsb_installed():
    #
    # https://mesonbuild.com/Unit-tests.html#skipped-tests-and-hard-errors
    #
    if not YCSB_HOME:
        print("WARNING: HSE_TEST_YCSB_HOME config option not set, skipping test.")
        sys.exit(77)
    elif not os.path.isfile(os.path.join(YCSB_HOME, "bin", "ycsb")):
        print(f"WARNING: HSE_TEST_YCSB_HOME {YCSB_HOME} does not exist, skipping test.")
        sys.exit(77)


def is_device_monitoring_enabled():
    return MONITOR_DEVICES is not None and len(MONITOR_DEVICES) > 0


def is_reports_db_enabled():
    return bool(REPORTS_MONGO_URI)


def is_loaded():
    return bool(LOG_DIR)


def get_dict():
    if not is_loaded():
        raise Exception("Config not yet loaded")

    result = {
        "KVDB_NAME": KVDB_NAME,
        "LOG_DIR": str(LOG_DIR),
        "MONITOR_DEVICES": MONITOR_DEVICES,
        "REPORTS_MONGO_COLLECTION": REPORTS_MONGO_COLLECTION,
        "REPORTS_MONGO_DATABASE": REPORTS_MONGO_DATABASE,
        "REPORTS_MONGO_URI": REPORTS_MONGO_URI,
        "YCSB_HOME": str(YCSB_HOME),
    }

    return result


def load():
    global KVDB_NAME
    global LOG_DIR

    global MONITOR_DEVICES

    global REPORTS_MONGO_COLLECTION
    global REPORTS_MONGO_DATABASE
    global REPORTS_MONGO_URI

    global REPORTS_MONGO_USERNAME
    global REPORTS_MONGO_PASSWORD

    global YCSB_HOME

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

    parser.add_argument("--ycsb-home", type=str)

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
        print()
        print("HSE_TEST_YCSB_HOME")

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

    LOG_DIR = __get_option(args, "log_dir", "HSE_TEST_BENCHMARK_LOG_DIR", type=Path)
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

    YCSB_HOME = __get_option(
        args, "ycsb_home", "HSE_TEST_YCSB_HOME", default="/opt/hse-ycsb", type=Path
    )
