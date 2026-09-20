from setuptools import setup, find_packages

setup(
    name="lightrail-wisp-server",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "websockets>=12.0",
        "aiohttp>=3.9.0",
    ],
)
