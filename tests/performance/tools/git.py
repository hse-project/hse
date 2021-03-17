import subprocess


def get_sha(src_dir):
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()
    return sha


def get_git_info(src_dir):
    branch = (
        subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"])
        .decode()
        .strip()
    )
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()
    describe = subprocess.check_output(["git", "describe"]).decode().strip()

    result = {
        "branch": branch,
        "describe": describe,
        "sha": sha,
    }

    return result
