from setuptools import setup, find_packages

setup(
    name="dnlab-multinode",
    version="0.2.0",
    packages=find_packages(),
    install_requires=[
        "paramiko>=3.0",
        "click>=8.0",
        "pyyaml>=6.0",
        "rich>=13.0",
    ],
    extras_require={
        # API services (dnlab-multinode-api, image-sync API) only. The CLIs and
        # the lab-cleanup daemon do not import these.
        "api": [
            "fastapi>=0.115",
            "uvicorn[standard]>=0.34",
            "pydantic>=2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "dnlab-multinode=dnlab_multinode.cli:main",
            "dnlab-image-sync=dnlab_multinode.image_sync_cli:main",
            "dnlab-lab-cleanup=dnlab_multinode.lab_cleanup_cli:main",
            "dnlab-multinode-api=dnlab_multinode.api:main",
        ],
    },
)
