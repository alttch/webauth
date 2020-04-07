__version__ = '0.0.2'

import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='webauth',
    version=__version__,
    author='Altertech',
    author_email='div@altertech.com',
    description='flask auth/oauth wrapper',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/alttch/webauth',
    packages=setuptools.find_packages(),
    include_package_data=True,
    license='MIT',
    install_requires=[
        'pyaltt2>=0.0.70', 'flask', 'loginpass', 'authlib', 'sqlalchemy'
    ],
    classifiers=(
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Topic :: Software Development :: Libraries',
    ),
)
