SERVER_NAME = wormholed
CLI_NAME = wormhole

SHARED = \
	client \
	utils

CLI = \
	cli \
	main/$(CLI_NAME)

SERVER = \
	pkg/netaddr \
	pkg/proxy \
	server \
	main/$(SERVER_NAME)

COMBINED := $(SHARED) $(CLI) $(SERVER)

SHARED_DEPS = \
	github.com/raff/tls-ext \
	github.com/raff/tls-psk

# kubernetes/pkg/api is needed for pkg/proxy
# the other dependencies besides netns and netlink are for kubernetes
SERVER_DEPS = \
	github.com/GoogleCloudPlatform/kubernetes/pkg/api \
	github.com/fsouza/go-dockerclient \
	github.com/golang/glog \
	gopkg.in/v1/yaml \
	github.com/vishvananda/netns \
	github.com/vishvananda/netlink

CLI_DEPS =

TEST_DEPS =

COMBINED_DEPS := $(SHARED_DEPS) $(CLI_DEPS) $(SERVER_DEPS) $(TEST_DEPS)

uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))
gofiles = $(foreach d,$(1),$(wildcard $(d)/*.go))
testdirs = $(call uniq,$(foreach d,$(1),$(dir $(wildcard $(d)/*_test.go))))
goroot = $(addprefix ../../../,$(1))
unroot = $(subst ../../../,,$(1))

all: $(SERVER_NAME) $(CLI_NAME)

$(call goroot,$(COMBINED_DEPS)):
	go get $(call unroot,$@)

$(SERVER_NAME): $(call goroot,$(SHARED_DEPS)) $(call goroot,$(SERVER_DEPS)) $(call gofiles,$(SERVER)) $(call gofiles,$(SHARED))
	go build github.com/vishvananda/wormhole/main/wormholed

$(CLI_NAME): $(call goroot,$(SHARED_DEPS)) $(call goroot,$(CLI_DEPS)) $(call gofiles,$(CLI)) $(call gofiles,$(SHARED))
	go build github.com/vishvananda/wormhole/main/wormhole

.PHONY: $(call testdirs,$(COMBINED))
$(call testdirs,$(COMBINED)): $(call goroot,$(TEST_DEPS))
	sudo -E go test -v github.com/vishvananda/wormhole/$@

fmt:
	for dir in . $(COMBINED); do go fmt github.com/vishvananda/wormhole/$$dir; done

test: test-unit test-functional

test-unit: $(call testdirs,$(COMBINED))

.PHONY: pong
pong:
	$(MAKE) -C pong all

test-functional: $(SERVER_NAME) $(CLI_NAME) pong
	sudo -E go test -v functional_test.go

.PHONY: clean
clean:
	-rm wormhole wormholed

