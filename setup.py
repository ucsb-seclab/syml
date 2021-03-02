from setuptools import setup

with open("requirements.txt") as f:
    install_requires = f.read().strip().split("\n")

dependency_links = [link[link.find("+") + 1:] for link in install_requires if "+" in link]
install_requires = [req for req in install_requires if not "+" in req]

setup(
    name='syml',
    version='0.2.dev',
    packages=['syml'],
    install_requires=install_requires,
    dependency_links=dependency_links
)
