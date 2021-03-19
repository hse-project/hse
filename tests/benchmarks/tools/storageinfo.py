import os
import shutil
import subprocess

from tools import config


def save_mpool_info(tag):
    args = ["mpool", "list", "-Y", "-v", config.KVDB_NAME]
    out = os.path.join(config.LOG_DIR, f"mpool_list.{tag}.out")
    with open(out, "w") as fd:
        subprocess.run(args, stdout=fd, stderr=subprocess.STDOUT, check=True)


def save_diskstats(tag):
    out = os.path.join(config.LOG_DIR, f"diskstats.{tag}.out")
    shutil.copy("/proc/diskstats", out)
    os.chmod(out, 0o664)
    return out


def parse_diskstats(diskstats_path, basename=None):
    #
    # https://www.kernel.org/doc/Documentation/ABI/testing/procfs-diskstats
    #
    devices = config.MONITOR_DEVICES

    if basename is None:
        basenames = [os.path.basename(x) for x in devices]
    else:
        basenames = [basename]

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
