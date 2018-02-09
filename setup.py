from setuptools import setup

setup(name='IBMQuantumExperience',
      packages=['IBMQuantumExperience'],  # this must be the same as the name above
      version='1.8.27',  # this should match __init__.__version__
      author='IBM Research ETX',
      description='A Python library for the Quantum Experience API.',
      author_email='pacom@us.ibm.com',
      url='https://github.com/QISKit/qiskit-api-py',
      keywords=['ibm', 'quantum computer', 'quantum experience'],
      license='Apache-2.0',
      install_requires=[
          'requests',
          'requests_ntlm'
      ],
      classifiers=(
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'Natural Language :: English',
          'License :: OSI Approved :: Apache Software License',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3.6'
      ),
      zip_safe=False)
