import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="dependencytrack-py",
    version="0.0.3",
    author="Roberto Polli",
    author_email="robipolli@gmail.com",
    description="A simple wrapper for the Dependency Track REST API.",
    long_description=long_description,
    long_description_content_type="text/plain",
    url="https://github.com/ioggstream/dependencytrack-py",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
)
