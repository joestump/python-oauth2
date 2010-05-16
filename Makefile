ROOTCMD      = fakeroot
BUILD_NUMBER ?= 1

.PHONY: debian/changelog

debian/changelog:
	-git branch -D changelog
	git checkout -b changelog
	git-dch -a -N $(shell python setup.py --version) --debian-branch changelog \
            --snapshot --snapshot-number=$(BUILD_NUMBER)

dist:
	mkdir -p $@

deb: debian/changelog dist
	dpkg-buildpackage -r$(ROOTCMD) -us -uc
	mv ../python-oauth2_* dist/

test:
	python setup.py test --with-coverage --cover-package=oauth2

sdist:
	python setup.py sdist

clean:
	rm -rf dist && rm -fr *.egg && find . -name \*.pyc -print -delete
	$(ROOTCMD) debian/rules clean
