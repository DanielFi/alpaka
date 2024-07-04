from setuptools import setup


setup(
    name='alpaka',
    version='2.0',
    packages=['alpaka'],
    install_requires=[
        'lief',
        'click'
    ],
    entry_points='''
        [console_scripts]
        alpaka=alpaka.cli:main
    '''
)
