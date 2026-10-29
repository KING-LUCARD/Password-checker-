from setuptools import setup, find_packages

setup(
    name="password-strength-analyzer",
    version="1.0.0",
    description="Password Strength Analyzer and Entropy Calculator - Linux CLI Tool",
    py_modules=["password_analyzer"],
    install_requires=["zxcvbn>=4.4.0"],
    entry_points={
        "console_scripts": [
            "password-analyzer=password_analyzer:main",
        ],
    },
    python_requires=">=3.8",
)
