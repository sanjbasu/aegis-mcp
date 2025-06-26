from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mcp-security-remediation",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Comprehensive security remediation for Model Context Protocol (MCP) implementations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/mcp-security-remediation",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "aiohttp>=3.9.1",
        "cryptography>=41.0.7",
        "pyjwt>=2.8.0",
        "redis>=5.0.1",
        "pydantic>=2.5.3",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.4",
            "pytest-asyncio>=0.23.3",
            "pytest-cov>=4.1.0",
            "black>=23.12.1",
            "flake8>=7.0.0",
            "mypy>=1.8.0",
        ],
        "cloud": [
            "boto3>=1.34.14",
            "azure-identity>=1.15.0",
            "google-cloud-secret-manager>=2.18.1",
        ],
    },
)
