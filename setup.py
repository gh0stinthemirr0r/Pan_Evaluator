#!/usr/bin/env python3
"""
Setup script for PanOS Evaluator
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="panos-evaluator",
    version="1.0.0",
    author="PanOS Evaluator Team",
    author_email="",
    description="A comprehensive GUI application for analyzing and optimizing Palo Alto Networks firewall security policies",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/gh0stinthemirr0r/pan_evaluator",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "panos-evaluator=evaluator:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords="palo alto networks firewall security policy analysis optimization",
    project_urls={
        "Bug Reports": "https://github.com/gh0stinthemirr0r/pan_evaluator/issues",
        "Source": "https://github.com/gh0stinthemirr0r/pan_evaluator",
        "Documentation": "https://github.com/gh0stinthemirr0r/pan_evaluator#readme",
    },
)
