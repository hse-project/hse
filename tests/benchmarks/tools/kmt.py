import os
from typing import List

from tools import config
from tools.base import BaseTest
from tools.helpers import shlex_join


class KmtTest(BaseTest):
    def __init__(self, name: str, args: List[str]):
        super().__init__(name, "kmt")

        self.args = self.__fix_args(args)
        self.kmt_out_path = None
        self.report["kmt"] = {
            "args": self.args,
            "cmdline": shlex_join(self.args),
        }

    @staticmethod
    def __fix_args(args: List):
        new_args = ["kmt"] + list(args)

        if not any([arg.startswith("-L") for arg in args]):
            new_args.append("-L")
        if not any([arg.startswith("-s") for arg in args]):
            new_args.append("-s1")

        new_args.append("%s/%s" % (config.KVDB_NAME, config.KVS_NAME))

        return new_args

    def execute(self):
        super()._init_storage()

        self.kmt_out_path = super()._run_command(self.args)

        self._postprocess()
        self._save_summary()
        super()._save_report()

    def _postprocess(self):
        init_phase = {
            "name": "init",
            "operations": [],
        }
        test_phase = {
            "name": "test",
            "operations": [],
        }

        with open(self.kmt_out_path) as fd:
            for line in fd:
                if line.startswith("iclose"):
                    record = line.split()
                    total_puts = int(record[6])
                    run_time_ms = int(record[15])
                    puts_per_second = int(total_puts / (run_time_ms / 1000.0))

                    init_phase["run_time_ms"] = run_time_ms

                    init_put_operation = {
                        "name": "put",
                        "throughput": puts_per_second,
                    }

                    init_phase["operations"].append(init_put_operation)
                elif line.startswith("tclose"):
                    record = line.split()
                    total_gets, total_puts = int(record[5]), int(record[6])
                    run_time_ms = int(record[15])
                    puts_per_second = int(total_puts / (run_time_ms / 1000.0))
                    gets_per_second = int(total_gets / (run_time_ms / 1000.0))

                    test_phase["run_time_ms"] = run_time_ms

                    test_put_operation = {
                        "name": "put",
                        "throughput": puts_per_second,
                    }
                    test_get_operation = {
                        "name": "get",
                        "throughput": gets_per_second,
                    }

                    test_phase["operations"].extend(
                        [test_put_operation, test_get_operation]
                    )
                elif line.startswith("slatency"):
                    record = line.split()
                    phase = record[1]
                    op = record[2]
                    (
                        lat_min,
                        lat_max,
                        lat_avg,
                        lat_p90,
                        lat_p95,
                        lat_p99,
                        lat_p99_9,
                        lat_p99_99,
                    ) = [int(x) for x in record[5:13]]

                    if phase == "init":
                        assert op == "put"
                        operation_dict = init_put_operation
                    elif phase == "test":
                        assert op in ["get", "put"]
                        if op == "put":
                            operation_dict = test_put_operation
                        elif op == "get":
                            operation_dict = test_get_operation
                        else:
                            assert False
                    else:
                        assert False

                    operation_dict["latency_us"] = {
                        "avg": lat_avg,
                        "max": lat_max,
                        "min": lat_min,
                        "percentiles": [
                            [90, lat_p90],
                            [95, lat_p95],
                            [99, lat_p99],
                            [99.9, lat_p99_9],
                            [99.99, lat_p99_99],
                        ],
                    }

        self.report["phases"] = [
            init_phase,
            test_phase,
        ]

    def _save_summary(self):
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
            for op in phase["operations"]:
                op_name = op["name"]
                summary += "%s %ss per second:  %d\n" % (
                    phase_name,
                    op_name,
                    op["throughput"],
                )
                summary += "%s %s latencies:    %s\n" % (
                    phase_name,
                    op_name,
                    op["latency_us"],
                )
            summary += "\n"

        summary = summary.rstrip()

        print(summary)
        print()

        summary_path = os.path.join(self.log_dir, "summary.txt")

        with open(summary_path, "w") as fd:
            fd.write(summary)
