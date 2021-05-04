import os
import shutil
import subprocess

from tools import config


def save_mpool_info(dest_dir, tag: str):
    args = ["mpool", "list", "-Y", "-v", config.KVDB_HOME]
    out = os.path.join(dest_dir, f"mpool_list.{tag}.out")
    with open(out, "w") as fd:
        subprocess.run(args, stdout=fd, stderr=subprocess.STDOUT, check=True)


def save_diskstats(dest_dir, tag: str):
    out = os.path.join(dest_dir, f"diskstats.{tag}.out")
    shutil.copy("/proc/diskstats", out)
    os.chmod(out, 0o664)
    return out


def generate_diskstats_report(diskstats_before_path, diskstats_after_path):
    result = {
        "after": {"overall": {}, "devices": [],},
        "before": {"overall": {}, "devices": [],},
        "delta": {"overall": {}, "devices": [],},
    }

    d1 = parse_diskstats(diskstats_before_path)
    d2 = parse_diskstats(diskstats_after_path)

    result["before"]["overall"] = d1
    result["after"]["overall"] = d2

    for key in ["bytes_read", "bytes_written", "bytes_discarded"]:
        result["delta"]["overall"][key] = d2[key] - d1[key]

    for device in config.MONITOR_DEVICES:
        basename = os.path.basename(device)

        d1 = parse_diskstats(diskstats_before_path, device=device)
        d2 = parse_diskstats(diskstats_after_path, device=device)

        d1["name"] = basename
        d2["name"] = basename

        result["before"]["devices"].append(d1)
        result["after"]["devices"].append(d2)

        delta = {"name": basename}

        for key in ["bytes_read", "bytes_written", "bytes_discarded"]:
            delta[key] = d2[key] - d1[key]

        result["delta"]["devices"].append(delta)

    return result


def parse_diskstats(diskstats_path, device: str = None):
    #
    # https://www.kernel.org/doc/Documentation/ABI/testing/procfs-diskstats
    #
    if device is None:
        basenames = [os.path.basename(x) for x in config.MONITOR_DEVICES]
    else:
        basenames = [os.path.basename(device)]

    bytes_read = None
    bytes_written = None
    bytes_discarded = None

    if basenames:
        with open(diskstats_path) as fd:
            for line in fd:
                if any([f" {x} " in line for x in basenames]):
                    fields = line.split()

                    if bytes_read is None:
                        bytes_read = 0
                    if bytes_written is None:
                        bytes_written = 0

                    bytes_read += int(fields[5]) * 512
                    bytes_written += int(fields[9]) * 512

                    if len(fields) > 14:
                        if bytes_discarded is None:
                            bytes_discarded = 0
                        bytes_discarded += int(fields[16]) * 512

    result = {
        "bytes_read": bytes_read,
        "bytes_written": bytes_written,
        "bytes_discarded": bytes_discarded,
    }

    return result
