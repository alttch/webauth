VERSION=0.0.18

all:
	@echo "what do you want to build today?"

ver:
	find . -type f -name "*.py" -exec sed -i "s/^__version__ = .*/__version__ = '${VERSION}'/g" {} \;

d: test-headless build

build:
	rm -rf dist build webauth.egg-info
	python3 setup.py sdist

pub:
	jks build webauth

pub-test:
	twine upload -r test dist/*

pub-pypi: upload-pypi

upload-pypi:
	twine upload dist/*

install:
	python3 setup.py build
	sudo python3 setup.py install

test:
	cd tests && pytest -x ./test.py

test-headless:
	cd tests && HEADLESS_TEST=1 pytest -x ./test.py

clean:
	rm -rf dist build webauth.egg-info
