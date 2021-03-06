# Docker-specific Makefile for Netbricks Project
# ==============================================

BASE_DIR = $(shell pwd)
SANDBOX ?= yangzhou1997/sandbox:nightly-2019-05-15

MOUNTS = -v /lib/modules:/lib/modules \
         -v /usr/src:/usr/src \
         -v /dev/hugepages:/dev/hugepages

.PHONY: pull-sandbox run run-lint run-tests

pull-sandbox:
	@docker pull $(SANDBOX)

run: pull-sandbox
	@docker run -it --rm --privileged --network=host \
		--user=root \
		-w /opt \
        $(MOUNTS) \
		-v $(BASE_DIR):/opt/NetBricks \
		-v $(BASE_DIR)/moongen:/opt/moongen \
		-m 1g \
		-v $(BASE_DIR)/../jemalloc:/opt/jemalloc \
		-v $(BASE_DIR)/../traffic:/opt/traffic \
		-v /usr/local/bin/heaptrack:/usr/local/bin/heaptrack \
		-v /usr/local/lib/heaptrack:/usr/local/lib/heaptrack \
		-v /usr/lib/x86_64-linux-gnu/libunwind.so.8:/usr/lib/x86_64-linux-gnu/libunwind.so.8 \
		-v /usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1:/usr/lib/x86_64-linux-gnu/libunwind.so.8.0.1 \
		$(SANDBOX) /bin/bash

run-tests: pull-sandbox
	@docker run -it --rm --privileged --network=host \
		-w /opt/netbricks \
		$(MOUNTS) \
		-v $(BASE_DIR):/opt/NetBricks \
		-v $(BASE_DIR)/moongen:/opt/moongen \
		$(SANDBOX) make test

run-lint: pull-sandbox
	@docker run -it --rm --privileged --network=host \
		-w /opt/netbricks \
		$(MOUNTS) \
		-v $(BASE_DIR):/opt/NetBricks \
		-v $(BASE_DIR)/moongen:/opt/moongen \
		$(SANDBOX) make lint
