APP     := wkmailsync
CMD     := ./cmd/wkmailsync
DIST    := dist

.PHONY: build test lint clean release-version

## build: compile binary for the current platform
build:
	go build -trimpath -ldflags "-s -w -X main.version=$$(git describe --tags --abbrev=0 2>/dev/null || echo dev)" -o $(DIST)/$(APP) $(CMD)

## test: run tests
test:
	go test ./...

## lint: vet the code
lint:
	go vet ./...

## clean: remove build artifacts
clean:
	rm -rf $(DIST)

## release-version: bump patch version, update package files, commit, tag, and push
release-version:
	@CURRENT=$$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0"); \
	MAJOR=$$(echo $$CURRENT | sed 's/v\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\).*/\1/'); \
	MINOR=$$(echo $$CURRENT | sed 's/v\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\).*/\2/'); \
	PATCH=$$(echo $$CURRENT | sed 's/v\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\).*/\3/'); \
	NEXT="v$$MAJOR.$$MINOR.$$((PATCH + 1))"; \
	PKGVER="$$MAJOR.$$MINOR.$$((PATCH + 1))"; \
	echo "Current: $$CURRENT → Next: $$NEXT"; \
	sed -i "s/^var version = .*/var version = \"$$PKGVER\"/" cmd/wkmailsync/main.go; \
	sed -i "s/^pkgver=.*/pkgver=$$PKGVER/" installers/arch/PKGBUILD; \
	sed -i "s/^Version:.*/Version:        $$PKGVER/" installers/rpm/wkmailsync.spec; \
	sed -i "s/^Version:.*/Version: $$PKGVER/" installers/debian/control; \
	git add cmd/wkmailsync/main.go installers/arch/PKGBUILD installers/rpm/wkmailsync.spec installers/debian/control; \
	git commit -m "chore(release): update package version to $$PKGVER"; \
	git push origin HEAD; \
	git tag -a "$$NEXT" -m "Release $$NEXT"; \
	git push origin "$$NEXT"; \
	echo "Pushed $$NEXT — release workflow triggered"
