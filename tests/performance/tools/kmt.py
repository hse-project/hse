import shlex

from tools import config
from tools.base import BaseTest


__KMT_KWARGS = [
    "kbinsz",  # -B, -b
    "check",  # -c
    "keyfmt",  # -f
    "recmax",  # -i
    "vlenmax",  # -l
    "kmt_properties",  # -o
    "verify_reads",  # -R
    "seed",  # -S
    "swsecs",  # -T
    "wpct",  # -w
    "sync_ms",  # -y
]


class KmtOptions:
    def __init__(
        self,
        kbinsz: int = None,
        check: bool = None,
        keyfmt: str = None,
        recmax: int = None,
        vlenmax: int = None,
        kmt_properties=None,
        verify_reads: bool = None,
        seed: int = None,
        swsecs: int = None,
        wpct: int = None,
        sync_ms: int = None,
    ):
        self.kbinsz = kbinsz
        self.check = check
        self.keyfmt = keyfmt
        self.recmax = recmax
        self.vlenmax = vlenmax
        if kmt_properties is None:
            self.kmt_properties = {}
        else:
            self.kmt_properties = kmt_properties
        self.verify_reads = verify_reads
        self.seed = seed
        self.swsecs = swsecs
        self.wpct = wpct
        self.sync_ms = sync_ms

    def to_dict(self):
        d = {}
        if self.kbinsz is not None:
            d["kbinsz"] = self.kbinsz
        if self.check is not None:
            d["check"] = self.check
        if self.keyfmt is not None:
            d["keyfmt"] = self.keyfmt
        if self.recmax is not None:
            d["recmax"] = self.recmax
        if self.vlenmax is not None:
            d["vlenmax"] = self.vlenmax
        if self.kmt_properties:
            d["kmt_properties"] = self.kmt_properties
        if self.verify_reads:
            d["verify_reads"] = self.verify_reads
        if self.seed:
            d["seed"] = self.seed
        if self.swsecs:
            d["swsecs"] = self.swsecs
        if self.wpct:
            d["wpct"] = self.wpct
        if self.sync_ms:
            d["sync_ms"] = self.sync_ms

        return d


class KmtTest(BaseTest):
    @staticmethod
    def __generate_args(options):
        args = ["kmt"]

        if options.kbinsz is not None:
            if options.kbinsz == 8:
                args.append("-b")
            else:
                args.append("-B%d" % options.binsz)
        if options.check is True:
            args.append("-c")
        if options.keyfmt is not None:
            args.append("-f%s" % options.keyfmt)
        if options.recmax is not None:
            args.append("-i%d" % options.recmax)
        if options.vlenmax is not None:
            args.append("-l%d" % options.vlenmax)
        if options.kmt_properties is not None:
            for key, value in options.kmt_properties.items():
                args.append("-o")
                args.append("%s=%s" % (key, value))
        if options.verify_reads is not None:
            if options.verify_reads is False:
                args.append("-R")
        if options.seed is not None:
            args.append("-S%d" % options.seed)
        if options.swsecs is not None:
            args.append("-t%d" % options.swsecs)
        if options.wpct is not None:
            args.append("-w%d" % options.wpct)
        if options.sync_ms is not None:
            args.append("-y%d" % options.sync_ms)

        args.append("-s1")
        args.append("-L")
        args.append("%s/%s" % (config.KVDB_NAME, config.KVS_NAME))

        return args

    def __init__(self, name, options):
        super().__init__(name, "kmt")
        self.options = options
        self.args = self.__generate_args(options)

        self.report["kmt"] = {
            "cmdline": shlex.join(self.args),
            "options": self.options.to_dict(),
        }

    def execute(self):
        super()._init_storage()

        kmt_out_path = super()._run_command(self.args)

        self.__postprocess(kmt_out_path)
        super()._save_report()

    def __postprocess(self, kmt_out_path):
        init_phase = {
            "name": "init",
            "operations": [],
        }
        test_phase = {
            "name": "test",
            "operations": [],
        }

        with open(kmt_out_path) as fd:
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
