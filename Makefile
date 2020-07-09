NAME=aws_usersync
AUTHOR=appvia
AUTHOR_EMAIL=info@appvia.io
REGISTRY=quay.io
ROOT_DIR=${PWD}
HARDWARE=$(shell uname -m)
GIT_SHA=$(shell git --no-pager describe --always --dirty)
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%I:%M:%S%p')
VERSION ?= v$(shell awk '/version .*=/ { print $$3 }' cmd/aws_usersync/main.go | sed 's/"//g')
DEPS=$(shell go list -f '{{range .TestImports}}{{.}} {{end}}' ./...)
PACKAGES=$(shell go list ./...)
LFLAGS ?= -X main.GitSHA=${GIT_SHA}
VETARGS ?= -asmdecl -atomic -bool -buildtags -copylocks -methods -nilfunc -printf -rangeloops -structtag -unsafeptr
CGO_ENABLED ?= 0

.PHONY: test build static release lint cover vet glide-install

default: build

golang:
	@echo "--> Go Version"
	@go version

build: glide-install
	@echo "--> Compiling the project"
	mkdir -p bin
	CGO_ENABLED=${CGO_ENABLED} GOOS=linux go build -ldflags "${LFLAGS}" -o bin/${NAME} cmd/${NAME}/*.go

static: golang glide-install
	@echo "--> Compiling the static binary"
	mkdir -p bin
	CGO_ENABLED=${CGO_ENABLED} GOOS=linux go build -a -tags netgo -ldflags "-w ${LFLAGS}" -o bin/${NAME}-${VERSION}-linux-amd64 cmd/${NAME}/*.go

docker:
	@echo "--> Building docker image"
	@docker build -t ${NAME} .

docker-release: docker
	@docker tag ${NAME} ${REGISTRY}/${AUTHOR}/${NAME}:${VERSION}
	@echo "--> Pushing docker image to ${REGISTRY}/${AUTHOR}/${NAME}:${VERSION}"
	@docker push ${REGISTRY}/${AUTHOR}/${NAME}:${VERSION}

release: static
	mkdir -p release
	gzip -c bin/${NAME} > release/${NAME}_${VERSION}_linux_${HARDWARE}.gz
	rm -f release/${NAME}

vet:
	@echo "--> Running go vet $(VETARGS) ."
	@go tool vet 2>/dev/null ; if [ $$? -eq 3 ]; then \
		go get golang.org/x/tools/cmd/vet; \
		fi
	@go vet $(VETARGS) $(PACKAGES)

lint:
	@echo "--> Running golint"
	@which golint 2>/dev/null ; if [ $$? -eq 1 ]; then \
		go get -u github.com/golang/lint/golint; \
		fi
	@golint .

gofmt:
	@echo "--> Running gofmt check"
	@gofmt -s -l ./... | grep -q \.go ; if [ $$? -eq 0 ]; then \
		echo "You need to runn the make format, we have file unformatted"; \
			gofmt -s -l *.go; \
			exit 1; \
		fi

bench:
	@echo "--> Running go bench"
	@go test -v -bench=.

clean:
	rm -rf ./bin 2>/dev/null
	rm -rf ./release 2>/dev/null

glide-install:
	@echo "--> Installing dependencies"
	@go get github.com/Masterminds/glide
	@glide install --strip-vendor

test:
	@echo "--> Running the tests"
	@if [ ! -d "vendor" ]; then \
		make glide-install; \
  fi
	@go test -v ${PACKAGES}
	@$(MAKE) vet
	@$(MAKE) cover
