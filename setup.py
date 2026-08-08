from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="ratelimitly",
    version="0.1.0",
    description="Official Python client library for RateLimitly high-performance rate limiting.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="RateLimitly Team",
    author_email="support@ratelimitly.com",
    url="https://github.com/ratelimitly-com/rl-python-client",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "dnspython>=2.0.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
