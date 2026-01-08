from setuptools import setup, find_packages

# Read the contents of your README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pg_simple_auth",  # The name of your package
    version="0.1.4",  # Fix: NameError in signup_oauth - email not defined
    author='Martyn Garcia',
    author_email='martyn@255bits.com',
    description="A simple asynchronous authentication module for PostgreSQL",
    long_description=long_description,  # Use the README file as the long description
    long_description_content_type="text/markdown",
    url="https://github.com/255BITS/pg_simple_auth",  # The URL of your project’s repository
    packages=find_packages(),  # Automatically find all packages in the directory
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Framework :: AsyncIO",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: Session",
        "Topic :: Security :: Cryptography",
    ],
    python_requires='>=3.8',
    install_requires=[
        "asyncpg>=0.21",  # Ensure compatibility with asyncpg 0.21 and above
        "passlib>=1.7.4",  # Ensure compatibility with passlib 1.7.4 and above
        "PyJWT>=2.1.0",  # Ensure compatibility with PyJWT 2.1.0 and above
    ],
    include_package_data=True,  # Include other files specified in MANIFEST.in
    license="MIT",  # License for the package
)
