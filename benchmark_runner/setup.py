from setuptools import setup, find_packages

setup(
    name="testingcoderev1",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        "flask",
        "pymongo",
        "gridfs",
        "requests",
        "werkzeug",
        "ecdsa",
        "qrcode",
        "PyPDF2",
        "reportlab",
        "pillow", 
        "waitress"
    ],
    entry_points={
        "console_scripts": [
            "start-node=testingcoderev1.node1.app:main"
        ]
    }
)
