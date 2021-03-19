import subprocess


def get_git_info(src_dir):
    branch = (
        subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"])
        .decode()
        .strip()
    )
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()
    describe = subprocess.check_output(["git", "describe"]).decode().strip()

    cp = subprocess.run(["git", "diff", "--quiet"])
    dirty = bool(cp.returncode != 0)

    result = {
        "branch": branch,
        "describe": describe,
        "dirty": dirty,
        "sha": sha,
    }

    return result
