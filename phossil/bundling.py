import shutil
import subprocess
import sys
from pathlib import Path

import jsii
import aws_cdk as cdk
from aws_cdk import aws_lambda as lambda_

# The Lambdas run on arm64 (Graviton), so dependency wheels are always
# resolved for that target regardless of the machine performing bundling.
TARGET_PYTHON_VERSION = "3.14"
TARGET_PLATFORM = "manylinux2014_aarch64"


def pip_install_args() -> list:
    return [
        "--only-binary=:all:",
        "--platform",
        TARGET_PLATFORM,
        "--python-version",
        TARGET_PYTHON_VERSION,
        "--implementation",
        "cp",
    ]


def bundling_command() -> str:
    args = " ".join(pip_install_args())
    return f"pip install -r requirements.txt {args} -t /asset-output && cp -au . /asset-output"


@jsii.implements(cdk.ILocalBundling)
class LocalPipBundling:
    """Fallback bundler used when Docker is unavailable.

    phossil's Lambda dependencies are pure-Python, so resolving wheels for the
    Lambda's target platform with pip produces the same artifact that bundling
    inside the official runtime image would. When Docker is present, this
    bundler declines and CDK uses the runtime image instead.
    """

    def __init__(self, source_dir: Path):
        self.source_dir = source_dir

    @jsii.member(jsii_name="tryBundle")
    def try_bundle(self, output_dir: str, options: cdk.BundlingOptions) -> bool:
        if shutil.which("docker"):
            return False

        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--quiet",
                "--target",
                output_dir,
                *pip_install_args(),
                "-r",
                str(self.source_dir / "requirements.txt"),
            ]
        )
        shutil.copytree(
            self.source_dir,
            output_dir,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        return True


def bundled_lambda_code(source_dir: Path, runtime) -> lambda_.Code:
    return lambda_.Code.from_asset(
        str(source_dir),
        bundling=cdk.BundlingOptions(
            image=runtime.bundling_image,
            command=["bash", "-c", bundling_command()],
            local=LocalPipBundling(source_dir),
        ),
    )
