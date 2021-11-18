# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

import json
import os
import re
import shutil
from typing import List

from tools import config
from tools.base import BaseTest


class DBbenchCommandInfo:
    def __init__(self, args, benchmark_name, record_count, dest_dir):
        self.args = args
        self.benchmark_name = benchmark_name
        self.record_count = record_count
        self.dest_dir = dest_dir
        self.completed_info = None
        self.compact_completed_info = None


class DBbenchTest(BaseTest):
    def __init__(self, name: str, cmdlist: List[List[str]], compact=True):
        super().__init__(name, "dbbench")

        self.compact = compact
        self.compact_args = [config.HSE_EXECUTABLE, "kvdb", "compact", config.KVDB_HOME]
        self.dbbench_executable_path = shutil.which("db_bench")
        self.cwd = os.path.dirname(self.dbbench_executable_path)

        self.command_info_list = self.__preprocess_commands(cmdlist)

        self.report["dbbench"] = {
            "cwd": str(self.cwd),
            "executable_path": str(self.dbbench_executable_path),
        }

    def __preprocess_commands(self, cmdlist):
        command_info_list = []

        for arglist in cmdlist:
            info = self.__preprocess_dbbench_args(arglist)
            command_info_list.append(info)

        return command_info_list

    def __preprocess_dbbench_args(self, args: List[str]):
        db_param = "--db={}".format(config.KVDB_HOME)
        kvs_param = "--kvs={}".format(config.KVS_NAME)
        new_args = [
            self.dbbench_executable_path,
            db_param,
            kvs_param,
        ]
        new_args += list(args)
        for word in args:
            if "--benchmarks" in word:
                benchmark_name = word.split("=")[1]
                if "," in benchmark_name:
                    raise Exception("Cannot pass more than one benchmark")
            if "--num" in word:
                record_count = int(word.split("=")[1])

        dest_dir = os.path.join(self.log_dir, benchmark_name)
        info = DBbenchCommandInfo(new_args, benchmark_name, record_count, dest_dir)
        return info

    def execute(self):
        super()._execute_init()

        for command_info in self.command_info_list:
            completed_info = super()._run_command(
                command_info.args,
                cwd=self.cwd,
                dest_dir=command_info.dest_dir,
            )
            command_info.completed_info = completed_info

            if self.compact:
                dest_dir = os.path.join(
                    command_info.dest_dir,
                    "..",
                    f"{command_info.benchmark_name}_compact",
                )

                compact_completed_info = super()._run_command(
                    self.compact_args, dest_dir=dest_dir, tool_name="hse_compact_kvdb"
                )
                command_info.compact_completed_info = compact_completed_info

        self._postprocess()
        self._print_and_save_summary()
        super()._save_report()

    def _postprocess(self):
        phases = []

        for info in self.command_info_list:
            completed_info = info.completed_info

            phase_dict = {
                "name": info.benchmark_name,
                "operations": [],
                "start_timestamp_ms": completed_info.start_timestamp_ms,
                "end_timestamp_ms": completed_info.end_timestamp_ms,
                "run_time_ms": completed_info.run_time_ms,
            }

            if completed_info.diskstats:
                phase_dict["diskstats"] = completed_info.diskstats

            out_file = os.path.join(info.dest_dir, "dbbench.out")
            fp = open(out_file, "r")
            Lines = fp.readlines()
            metrics_lookup = [
                "Min",
                "Median",
                "Max",
                "Average",
                "StdDev",
            ]

            summary = {
                "count": info.record_count,
                "name": "",
                "latency_us": [],
                "throughput": None,
            }
            if info.benchmark_name in ["fillseq", "fillrandom", "overwrite"]:
                summary["name"] = "put"
            elif info.benchmark_name == "readwhilewriting":
                summary["name"] = "putget"
            else:
                summary["name"] = "get"

            latency_dict = {}

            # Finds the exact match of metric string in a line and format it to fetch the
            # corresponding value for that metric.
            for metric in metrics_lookup:
                for line in Lines:
                    if re.search(r"\b{}\b".format(metric), line):
                        formatted_line = line.split()
                        for i, val in enumerate(formatted_line):
                            # Strip special characters from formatted line values, to match the lookup word
                            val = val.strip(":;")
                            if val == metric:
                                if val == "Average":
                                    latency_dict["avg"] = float(
                                        formatted_line[i + 1].strip()
                                    )
                                else:
                                    latency_dict[metric.lower()] = float(
                                        formatted_line[i + 1].strip()
                                    )
                        break

            # Manually calculating throughput in ops/sec for hse
            run_time_secs = phase_dict["run_time_ms"] // 1000
            summary["throughput"] = info.record_count // run_time_secs
            summary["latency_us"].append(latency_dict)
            phase_dict["operations"].append(summary)
            phases.append(phase_dict)

            if self.compact:
                completed_info = info.compact_completed_info

                phase_dict = {
                    "name": f"{info.benchmark_name}_compact",
                    "operations": [],
                    "start_timestamp_ms": completed_info.start_timestamp_ms,
                    "end_timestamp_ms": completed_info.end_timestamp_ms,
                    "run_time_ms": completed_info.run_time_ms,
                }

                if completed_info.diskstats:
                    phase_dict["diskstats"] = completed_info.diskstats

                phases.append(phase_dict)

        self.report["phases"] = phases
