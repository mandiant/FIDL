from setuptools import setup


def readme():
    with open('README.rst') as f:
        return f.read()


setup(name='FIDL',
      version='1.0',
      description='Wrapper for the IDA decompiler API',
      classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Disassemblers',
      ],
      keywords='ida decompiler api vulnerability research reversing malware',
      url='https://ghe.eng.fireeye.com/otf/FIDL',
      author='The Council of Pwners',
      author_email='carlos.garcia@fireeye.com',
      license='MIT',
      install_requires=[
        'networkx',
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
