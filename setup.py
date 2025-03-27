from setuptools import find_packages, setup

setup(
    name="pyiotdevice",
    version="1.0.17",
    packages=find_packages(),
    install_requires=[
        "pycryptodome",
    ],
    author="iota Labs",
    author_email="info@iotalabs.co.in",
    description="A Python library for IoT device security and communication",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/daikin-br/pyiotdevice",
    project_urls={
        "Source": "https://github.com/daikin-br/pyiotdevice",
        "Bug Tracker": "https://github.com/daikin-br/pyiotdevice/issues",
        "GitHub Stats": "https://github-readme-stats.vercel.app/api?username=daikin-br&repo=pyiotdevice",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
)
