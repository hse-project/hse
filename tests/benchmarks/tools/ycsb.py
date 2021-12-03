# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

import json
import os
from typing import List

from tools import config
from tools.base import BaseTest


def __get_workload_properties(workload_file_path):
    result = {}

    with open(workload_file_path) as fd:
        for line in fd:
            if "=" in line:
                tmp = line.split("=")
                key, value = tmp[0], "=".join(tmp[1:])
                result[key] = value

    return result


def __get_cmdline_properties(args):
    result = {}

    for idx, arg in enumerate(args):
        if arg == "-p":
            if (idx + 1) >= len(args):
                raise Exception(
                    "-p option to YCSB requires an argument (args: %s)" % args
                )
            else:
                tmp = args[idx + 1].split("=")
                key, value = tmp[0], "=".join(tmp[1:])
                result[key] = value

    return result


def merge_properties(workload_file_path, args):
    properties = __get_workload_properties(workload_file_path)

    cmdline_properties = __get_cmdline_properties(args)

    properties.update(cmdline_properties)

    return properties


class YcsbCommandInfo:
    def __init__(self, args, properties, workload_name, dest_dir):
        self.args = args
        self.properties = properties
        self.workload_name = workload_name
        self.dest_dir = dest_dir
        self.completed_info = None
        self.compact_completed_info = None

        # The hse binding uses this property for the KVS name
        self.table = self.properties.get("table", "usertable")


class YcsbTest(BaseTest):
    def __init__(self, name: str, cmdlist: List[List[str]], compact=True):
        super().__init__(name, "ycsb")

        config.check_ycsb_installed()

        self.compact = compact
        self.compact_args = [config.HSE_EXECUTABLE, "kvdb", "compact", config.KVDB_HOME]
        self.cwd = config.YCSB_HOME

        self.ycsb_executable_path = os.path.join(config.YCSB_HOME, "bin", "ycsb")
        self.ycsb_exportfile_path = os.path.join(self.log_dir, "ycsb_results.json")

        self.command_info_list = self.__preprocess_commands(cmdlist)

        self.report["ycsb"] = {
            "cwd": str(self.cwd),
            "executable_path": str(self.ycsb_executable_path),
        }

    def execute(self):
        super()._execute_init()

        for command_info in self.command_info_list:
            completed_info = super()._run_command(
                command_info.args, cwd=config.YCSB_HOME, dest_dir=command_info.dest_dir
            )
            command_info.completed_info = completed_info

            if self.compact:
                dest_dir = os.path.join(
                    command_info.dest_dir, "..", f"{command_info.workload_name}_compact"
                )

                compact_completed_info = super()._run_command(
                    self.compact_args, dest_dir=dest_dir, tool_name="hse_compact_kvdb"
                )
                command_info.compact_completed_info = compact_completed_info

        self._postprocess()
        self._print_and_save_summary()
        super()._save_report()

    def __preprocess_commands(self, cmdlist):
        command_info_list = []

        for arglist in cmdlist:
            info = self.__preprocess_ycsb_args(arglist)
            command_info_list.append(info)

        return command_info_list

    def __preprocess_ycsb_args(self, args: List[str]):
        new_args = ["python2", os.path.join("bin", "ycsb")] + list(args)

        if not any([arg.startswith("-s") for arg in args]):
            new_args.append("-s")

        if "-P" not in args:
            raise Exception("-P <workload-file> option is required by YCSB")
        else:
            arg_idx = args.index("-P") + 1
            if arg_idx >= len(args):
                raise Exception(
                    "-P option to YCSB requires an argument (args: %s)" % args
                )
            else:
                workload_file_path = os.path.join(self.cwd, args[arg_idx])

            properties = merge_properties(workload_file_path, args)

        if args[0] == "load":
            workload_name = "load"
        else:
            workload_name = os.path.basename(workload_file_path)

        if "exporter" in properties:
            raise Exception("Cannot override 'exporter' property")
        else:
            new_args.extend(
                [
                    "-p",
                    "exporter=site.ycsb.measurements.exporter."
                    "JSONArrayMeasurementsExporter",
                ]
            )

        dest_dir = os.path.join(self.log_dir, workload_name)
        exportfile = os.path.join(dest_dir, "ycsb_results.json")

        if "exportfile" in properties:
            raise Exception("Cannot override 'exportfile' property")
        else:
            new_args.extend(["-p", "exportfile=%s" % exportfile])

        if "hdrhistogram.percentiles" not in properties:
            new_args.extend(
                ["-p", "hdrhistogram.percentiles=70,80,90,95,99,99.9,99.99"]
            )

        if "status.interval" not in properties:
            new_args.extend(["-p", "status.interval=1"])

        if ("threadcount" not in properties) and ("-threads" not in args):
            new_args.extend(["-threads", str(config.AVAILABLE_CPUS)])

        new_args.extend(["-p", "hse.kvdb_home=%s" % config.KVDB_HOME])

        info = YcsbCommandInfo(new_args, properties, workload_name, dest_dir)

        return info

    def _postprocess(self):
        failed = False
        fail_msg = None

        phases = []

        for info in self.command_info_list:
            completed_info = info.completed_info

            phase_dict = {
                "name": info.workload_name,
                "operations": [],
                "start_timestamp_ms": completed_info.start_timestamp_ms,
                "end_timestamp_ms": completed_info.end_timestamp_ms,
                "run_time_ms": completed_info.run_time_ms,
            }

            if completed_info.diskstats:
                phase_dict["diskstats"] = completed_info.diskstats

            ycsb_results_path = os.path.join(info.dest_dir, "ycsb_results.json")
            with open(ycsb_results_path) as fd:
                ycsb_data = json.load(fd)

            overall_throughput = [
                x
                for x in ycsb_data
                if x["metric"] == "OVERALL"
                and x["measurement"] == "Throughput(ops/sec)"
            ][0]["value"]

            phase_dict["operations"].append(
                {"name": "OVERALL", "throughput": overall_throughput}
            )

            for metric in [
                "READ",
                "UPDATE",
                "INSERT",
                "READ-MODIFY_WRITE",
                "SCAN",
                "CLEANUP",
            ]:
                if [x for x in ycsb_data if x["metric"] == f"{metric}-FAILED"]:
                    fail_msg = (
                        f"WARNING: One or more YCSB operations failed, "
                        f"going to fail test (metric={metric})"
                    )
                    print(fail_msg)
                    failed = True

                records = [x for x in ycsb_data if x["metric"] == metric]

                if not records:
                    continue

                operation = {
                    "name": metric,
                    "count": 0,
                    "latency_us": {},
                }
                percentiles = []

                for record in records:
                    measurement = record["measurement"]
                    value = record["value"]

                    if measurement == "Operations":
                        operation["count"] = value
                    elif measurement == "MinLatency(us)":
                        operation["latency_us"]["min"] = value
                    elif measurement == "MaxLatency(us)":
                        operation["latency_us"]["max"] = value
                    elif measurement == "AverageLatency(us)":
                        operation["latency_us"]["avg"] = value
                    elif measurement.endswith("PercentileLatency(us)"):
                        percentile = float(
                            measurement.rstrip("PercentileLatency(us)").rstrip("th")
                        )
                        percentiles.append([percentile, value])
                    elif measurement.startswith("Return="):
                        pass
                    else:
                        raise Exception(
                            f"Unexpected record in YCSB results "
                            f"(metric={metric}, measurement={measurement})"
                        )

                percentiles = sorted(percentiles, key=lambda x: x[0])
                operation["latency_us"]["percentiles"] = percentiles
                phase_dict["operations"].append(operation)

            phases.append(phase_dict)

            if self.compact:
                completed_info = info.compact_completed_info

                phase_dict = {
                    "name": f"{info.workload_name}_compact",
                    "operations": [],
                    "start_timestamp_ms": completed_info.start_timestamp_ms,
                    "end_timestamp_ms": completed_info.end_timestamp_ms,
                    "run_time_ms": completed_info.run_time_ms,
                }

                if completed_info.diskstats:
                    phase_dict["diskstats"] = completed_info.diskstats

                phases.append(phase_dict)

        self.report["phases"] = phases

        if failed:
            raise Exception(fail_msg)

    def _save_summary(self):
        pass
