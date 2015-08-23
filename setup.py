from setuptools import setup

setup(
    name='sacret',
    version='0.0.1',
    description='Plain file secret manager',
    url='https://github.com/rahcola/sacret',
    author='Jani Rahkola',
    author_email='jani.rahkola@iki.fi',
    license='MIT',
    install_requires=['docopt'],
    packages=['sacret'],
    package_data={
        "sacret": ['sacret.bash-completion']
    },
    scripts=['sacret/sacret.py']
)
