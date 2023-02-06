# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

import os
import subprocess
import time
from contextlib import ExitStack
from typing import Dict

from tools import config
from tools.fixtures import create_kvdb
from tools.helpers import shlex_join
from tools.monitors import spawn_pidstat, spawn_vmstat, spawn_iostat
from tools.report import (
    new_report,
    save_report_as_json,
    save_report_to_db,
)
from tools.storageinfo import save_diskstats, save_kvdb_info, generate_diskstats_report


class CompletedCommand:
    def __init__(
        self,
        start_timestamp_ms: int,
        end_timestamp_ms: int,
        diskstats: Dict[str, int] = None,
        out_path=None,
    ):
        self.start_timestamp_ms = start_timestamp_ms
        self.end_timestamp_ms = end_timestamp_ms
        self.diskstats = diskstats
        self.out_path = out_path

        self.run_time_ms = end_timestamp_ms - start_timestamp_ms


class BaseTest:
    def __init__(self, test_name: str, tool_name: str):
        self.test_name = test_name
        self.tool_name = tool_name

        self.start_diskstats_before_path = None

        self.start_timestamp_ms = None
        self.end_timestamp_ms = None

        if not config.is_loaded():
            config.load()

        self.log_dir = os.path.join(config.LOG_DIR, test_name)
        os.makedirs(self.log_dir, exist_ok=True)

        self.report = new_report()
        self.report["test_name"] = test_name
        self.report["tool_name"] = tool_name

    def _execute_init(self):
        create_kvdb()

    def _save_report(self):
        if self.start_timestamp_ms is not None:
            self.report["start_timestamp_ms"] = self.start_timestamp_ms
        if self.end_timestamp_ms is not None:
            self.report["end_timestamp_ms"] = self.end_timestamp_ms
            self.report["run_time_ms"] = self.end_timestamp_ms - self.start_timestamp_ms

        save_report_as_json(self.log_dir, self.report)

        if config.is_reports_db_enabled():
            save_report_to_db(self.report)

        print()
        print(f"Logs and artifacts saved to {self.log_dir}")

    def _print_and_save_summary(self):
        report = self.report

        summary = ""

        if "diskstats" in report:
            total_bytes_discarded = report["diskstats"]["overall"].get(
                "bytes_discarded", "Not recorded"
            )
            total_bytes_read = report["diskstats"]["overall"]["bytes_read"]
            total_bytes_written = report["diskstats"]["overall"]["bytes_written"]
        else:
            total_bytes_discarded = "Not recorded"
            total_bytes_read = "Not recorded"
            total_bytes_written = "Not recorded"

        summary += f"Bytes discarded:  {total_bytes_discarded}\n"
        summary += f"Bytes read:       {total_bytes_read}\n"
        summary += f"Bytes written:    {total_bytes_written}\n"
        summary += "\n"
        for phase in report["phases"]:
            phase_name = phase["name"]
            run_time_s = phase["run_time_ms"] // 1000

            summary += f"{phase_name} run time:  {run_time_s}s\n"

            for op in phase["operations"]:
                op_name = op["name"] if "name" in op else None
                if "throughput" in op:
                    summary += "%s %s(s) per second:  %d\n" % (
                        phase_name,
                        op_name,
                        op["throughput"],
                    )
                if "latency_us" in op:
                    summary += "%s %s latencies:  %s\n" % (
                        phase_name,
                        op_name,
                        op["latency_us"],
                    )

            if "diskstats" in phase:
                summary += f"{phase_name} diskstats:  {phase['diskstats']['overall']}\n"

            summary += "\n"

        summary = summary.rstrip()

        print(summary)
        print()

        summary_path = os.path.join(self.log_dir, "summary.txt")

        with open(summary_path, "w") as fd:
            fd.write(summary)

    def _run_command(self, args, cwd=None, dest_dir=None, tool_name=None):
        if dest_dir is None:
            dest_dir = self.log_dir

        if tool_name is None:
            tool_name = self.tool_name

        os.makedirs(dest_dir, exist_ok=True)

        out_path = os.path.join(dest_dir, f"{tool_name}.out")
        cmdline_path = os.path.join(dest_dir, f"{tool_name}.cmdline")

        is_device_monitoring_enabled = config.is_device_monitoring_enabled()

        cmdline = shlex_join(args)

        with open(cmdline_path, "w") as fd:
            fd.write(cmdline)
            fd.write("\n")

        with ExitStack() as stack:
            print(cmdline)
            print(f"Output will be written to {out_path}")
            print()

            if is_device_monitoring_enabled:
                diskstats_before_path = save_diskstats(dest_dir, "BEFORE")

            save_kvdb_info(dest_dir, "BEFORE")

            fd = open(out_path, "w")
            stack.enter_context(fd)

            end_timestamp_ms = None
            start_timestamp_ms = int(time.time() * 1000)

            if self.start_timestamp_ms is None:
                self.start_timestamp_ms = start_timestamp_ms

            vmstat_proc, vmstat_fd = spawn_vmstat(dest_dir)
            stack.enter_context(vmstat_fd)
            stack.enter_context(vmstat_proc)

            if is_device_monitoring_enabled:
                iostat_proc, iostat_fd = spawn_iostat(dest_dir)
                stack.enter_context(iostat_fd)
                stack.enter_context(iostat_proc)

            #
            # now launching the main process
            #
            proc = subprocess.Popen(args, cwd=cwd, stdout=fd, stderr=subprocess.STDOUT)
            stack.enter_context(proc)
            pid = proc.pid

            pidstat_proc, pidstat_fd = spawn_pidstat(dest_dir, pid)
            stack.enter_context(pidstat_fd)
            stack.enter_context(pidstat_proc)

            returncode = proc.wait()

            vmstat_proc.kill()

            if is_device_monitoring_enabled:
                iostat_proc.kill()

            if returncode != 0:
                raise Exception(
                    f"Command {args} failed with exit status {proc.returncode}"
                )

        end_timestamp_ms = int(time.time() * 1000)
        self.end_timestamp_ms = end_timestamp_ms

        save_kvdb_info(dest_dir, "AFTER")

        if is_device_monitoring_enabled:
            diskstats_after_path = save_diskstats(dest_dir, "AFTER")

            diskstats_report = generate_diskstats_report(
                diskstats_before_path, diskstats_after_path
            )

            if self.start_diskstats_before_path is None:
                self.start_diskstats_before_path = diskstats_before_path

            full_run_diskstats_report = generate_diskstats_report(
                self.start_diskstats_before_path, diskstats_after_path
            )

            self.report["diskstats"] = full_run_diskstats_report["delta"]
        else:
            diskstats_report = None

        completed_info = CompletedCommand(
            start_timestamp_ms,
            end_timestamp_ms,
            out_path=out_path,
            diskstats=diskstats_report["delta"] if diskstats_report else None,
        )

        return completed_info
