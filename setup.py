"""
Setup script for the Blockchain package.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="blockchain-core",
    version="1.0.0",
    author="Python Enthusiasts",
    author_email="",
    description="A simple but comprehensive blockchain implementation in Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pyenthusiasts/Blockchain",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "blockchain=cli.blockchain_cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
