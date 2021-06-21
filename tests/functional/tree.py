import subprocess


def collect_metrics(kvdb_name: str, kvs_name: str, return_values: bool = True):
    """
    collect the nf tree metrices
    """

    cmd =  f'../../tools/scripts/nf.tree.metrics -b {kvdb_name}/{kvs_name}'

    out = subprocess.check_output(cmd.split()).decode()

    if return_values:
        kvset = [line for line in out.split('\n') if line.startswith('t ')]
        vlen = [x.split()[6] for x in kvset]
        return int(vlen[0])
    else:
        return out