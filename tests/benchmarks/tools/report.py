# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

import copy
import getpass
import json
import os
import pathlib
import socket
from datetime import datetime, timezone

from tools import config
from tools.git import get_git_info


MODULE_DIR = pathlib.Path(__file__).parent.absolute()


def new_report():
    report = {
        "config": config.get_dict(),
        "hostname": socket.gethostname(),
        "git": get_git_info(MODULE_DIR),
        "uid": os.getuid(),
        "username": getpass.getuser(),
    }

    return report


def save_report_as_json(dest_dir, report):
    path = os.path.join(dest_dir, "report.json")

    with open(path, "w") as fd:
        json.dump(report, fd, indent=4, sort_keys=True)

    print(f"JSON report saved to {path}")


def save_report_to_db(report):
    try:
        import pymongo
    except ImportError:
        print(
            "WARNING: pymongo import not available, "
            "report will not be saved in Mongo"
        )
        return

    document = copy.deepcopy(report)

    # handle native datetime types that don't easily map to JSON
    def map_timestamp_fields(src, dst):
        if "start_timestamp_ms" in report:
            document["start_date"] = datetime.fromtimestamp(
                report["start_timestamp_ms"] / 1000, tz=timezone.utc
            )
        if "end_timestamp_ms" in report:
            document["end_date"] = datetime.fromtimestamp(
                report["end_timestamp_ms"] / 1000, tz=timezone.utc
            )

    map_timestamp_fields(report, document)

    for src_dict in report["phases"]:
        dst_dict = [d for d in document["phases"] if d["name"] == src_dict["name"]][0]
        map_timestamp_fields(src_dict, dst_dict)

    mongo_uri = config.REPORTS_MONGO_URI
    db_name = config.REPORTS_MONGO_DATABASE
    collection_name = config.REPORTS_MONGO_COLLECTION

    username = config.REPORTS_MONGO_USERNAME
    password = config.REPORTS_MONGO_PASSWORD

    try:
        with pymongo.MongoClient(mongo_uri) as mongo:
            db = mongo[db_name]

            if username:
                db.authenticate(username, password)

            collection = db[collection_name]
            inserted_id = collection.insert_one(document).inserted_id

            print(f"Report saved to MongoDB with _id={inserted_id}")
    except pymongo.errors.PyMongoError as e:
        print(
            f"WARNING: failed to save report to MongoDB "
            f'(mongo_uri={mongo_uri}, e="{e}")'
        )
