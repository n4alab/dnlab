from setuptools import find_packages, setup

setup(
    name="dnlab-runtime",
    version="0.1.0",
    packages=find_packages(),
    python_requires=">=3.11",
    entry_points={"console_scripts": ["dnlab-runtime=dnlab_runtime.cli:main"]},
)
