import os
import subprocess
import time
from contextlib import ExitStack

from tools import config
from tools.fixtures import make_kvdb
from tools.helpers import shlex_join
from tools.monitors import spawn_pidstat, spawn_vmstat, spawn_iostat
from tools.report import (
    new_report,
    save_report_as_json,
    save_report_to_db,
)
from tools.storageinfo import save_diskstats, save_mpool_info, parse_diskstats


class BaseTest:
    def __init__(self, test_name, tool_name):
        self.test_name = test_name
        self.tool_name = tool_name

        if not config.is_loaded():
            config.load()

        self.log_dir = os.path.join(config.LOG_DIR, test_name)
        os.makedirs(self.log_dir, exist_ok=True)

        self.report = new_report()
        self.report["test_name"] = test_name
        self.report["tool_name"] = tool_name

    def _init_storage(self):
        make_kvdb()

    def _save_report(self):
        save_report_as_json(self.log_dir, self.report)

        if config.is_reports_db_enabled():
            save_report_to_db(self.report)

        print()
        print(f"Logs and artifacts saved to {self.log_dir}")

    def _run_command(self, args):
        out_path = os.path.join(self.log_dir, f"{self.tool_name}.out")
        cmdline_path = os.path.join(self.log_dir, f"{self.tool_name}.cmdline")

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
                diskstats_before_path = save_diskstats(self.log_dir, "BEFORE")

            save_mpool_info(self.log_dir, "BEFORE")

            fd = open(out_path, "w")
            stack.enter_context(fd)

            end_timestamp_ms = None
            start_timestamp_ms = int(time.time() * 1000)

            vmstat_proc, vmstat_fd = spawn_vmstat(self.log_dir)
            stack.enter_context(vmstat_fd)
            stack.enter_context(vmstat_proc)

            if is_device_monitoring_enabled:
                iostat_proc, iostat_fd = spawn_iostat(self.log_dir)
                stack.enter_context(iostat_fd)
                stack.enter_context(iostat_proc)

            #
            # now launching the main process
            #
            proc = subprocess.Popen(args, stdout=fd, stderr=subprocess.STDOUT)
            stack.enter_context(proc)
            pid = proc.pid

            pidstat_proc, pidstat_fd = spawn_pidstat(self.log_dir, pid)
            stack.enter_context(pidstat_fd)
            stack.enter_context(pidstat_proc)

            proc.wait()
            vmstat_proc.kill()

            if is_device_monitoring_enabled:
                iostat_proc.kill()

        end_timestamp_ms = int(time.time() * 1000)

        save_mpool_info(self.log_dir, "AFTER")

        if is_device_monitoring_enabled:
            self.report["diskstats"] = {}

            overall = {}

            diskstats_after_path = save_diskstats(self.log_dir, "AFTER")

            d1 = parse_diskstats(diskstats_before_path)
            d2 = parse_diskstats(diskstats_after_path)

            for key in ["bytes_read", "bytes_written", "bytes_discarded"]:
                if key in d1 and d1[key] is not None:
                    overall[key] = d2[key] - d1[key]

            devices = []

            for device in config.MONITOR_DEVICES:
                basename = os.path.basename(device)

                tmp = {"name": basename}

                d1 = parse_diskstats(diskstats_before_path, basename=basename)
                d2 = parse_diskstats(diskstats_after_path, basename=basename)

                for key in ["bytes_read", "bytes_written", "bytes_discarded"]:
                    if key in d1 and d1[key] is not None:
                        tmp[key] = d2[key] - d1[key]

                devices.append(tmp)

            self.report["diskstats"]["overall"] = overall
            self.report["diskstats"]["devices"] = devices

        self.report["start_timestamp_ms"] = start_timestamp_ms
        self.report["end_timestamp_ms"] = end_timestamp_ms
        self.report["run_time_ms"] = end_timestamp_ms - start_timestamp_ms

        return out_path
