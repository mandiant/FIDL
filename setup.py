from setuptools import setup


def readme():
    with open('README.rst') as f:
        return f.read()


setup(name='FIDL',
      version='1.2',
      description='Wrapper for Hex-Rays decompiler API',
      classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Disassemblers',
      ],
      keywords='ida decompiler api vulnerability research reversing malware',
      url='https://github.com/fireeye/FIDL',
      author='FireEye FLARE Team',
      author_email='carlos.garcia@fireeye.com',
      license='MIT',
      install_requires=[
        'networkx',
        'six',
      ],
      extras_require={
        'dev': [
          'pytest',
          'pytest-pycodestyle',
          'sphinx_rtd_theme',
        ]
      },
      packages=['FIDL'],
      include_package_data=True,
      zip_safe=False)
