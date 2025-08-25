"""
Setup script for Event Horizon Python SDK
"""

from setuptools import setup, find_packages
import os

# Read README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "Event Horizon Python SDK - Professional SDK for secure messaging"

# Read requirements
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_path):
        with open(requirements_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name="event-horizon-sdk",
    version="2.0.0",
    author="Event Horizon Team",
    author_email="team@eventhorizon.chat",
    description="Professional Python SDK for Event Horizon Chat with end-to-end encryption",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/Mooncore-inc/Event-Horizon-host",
    project_urls={
        "Bug Tracker": "https://github.com/Mooncore-inc/Event-Horizon-host/issues",
        "Documentation": "https://github.com/Mooncore-inc/Event-Horizon-host/tree/main/SDK",
        "Source Code": "https://github.com/Mooncore-inc/Event-Horizon-host",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Communications :: Chat",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.8",
    install_requires=[
        "aiohttp>=3.8.0",
        "websockets>=11.0.0",
        "cryptography>=41.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "full": [
            "redis>=4.5.0",
            "asyncpg>=0.28.0",
            "celery>=5.3.0",
            "prometheus-client>=0.17.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "eh-sdk-test=SDK.test_sdk:main",
        ],
    },
    include_package_data=True,
    package_data={
        "SDK": ["*.md", "examples/*.py"],
    },
    keywords=[
        "messaging",
        "chat",
        "encryption",
        "cryptography",
        "websocket",
        "real-time",
        "did",
        "decentralized",
        "secure",
        "end-to-end",
    ],
    license="GPLv3",
    platforms=["any"],
    zip_safe=False,
)
