#!/usr/bin/env python

try:
    from setuptools import setup

except:
    from distutils.core import setup

import virustotal

setup(
    name = "virustotal",
    description = "Pythonic VirusTotal Public API 2.0 client",
    
    py_modules = ["virustotal"],
    test_suite = "tests",

    version = virustotal.__version__,
    author = virustotal.__author__,
    author_email = virustotal.__email__,
    url = "https://github.com/gawen/virustotal",
    license = virustotal.__license__,
    classifiers = [
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
