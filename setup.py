from setuptools import find_packages, setup

setup(
    name="pcap-decode",
    version="1.0.0",
    description="High-performance PCAP malware decoder, payload carver, and threat analyzer.",
    author="rbergman",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "rich>=12.0.0",
    ],
    entry_points={
        "console_scripts": [
            "pcap-decode=pcap_decode.cli:main",
        ],
    },
)
