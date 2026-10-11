SHELL := /bin/bash
.PHONY: all core cshim build package deploy-srl deploy-frr test test-srl test-frr test-unit clean

all: core cshim build package

core:
	$(MAKE) -C src/upstream/eigrp/eigrp/code libeigrp-core.a

cshim: core
	$(MAKE) -C src/cshim libsrl-cshim.a

build: cshim
	mkdir -p bin
	cd src/cmd/srl-eigrpd && go build -ldflags="-s -w" -a -v -o ../../../bin/srl-eigrpd .

package: build
	mkdir -p dist
	docker run --rm -v $(CURDIR):/tmp -w /tmp goreleaser/nfpm:latest package --config nfpm.yaml --target dist/srl-eigrpd_0.1.0_amd64.deb

deploy-srl: package
	sudo clab deploy -t topologies/srl-srl.clab.yml --reconfigure

deploy-frr: package
	sudo clab deploy -t topologies/srl-frr.clab.yml --reconfigure

test-srl:
	python3 -m pytest -v tests/test_srl_srl_peering.py

test-frr:
	python3 -m pytest -v tests/test_srl_frr_interop.py

test-unit: cshim
	cd src/cmd/srl-eigrpd && go test -race ./...

test: test-unit test-srl test-frr

clean:
	sudo clab destroy -t topologies/srl-srl.clab.yml --cleanup || true
	sudo clab destroy -t topologies/srl-frr.clab.yml --cleanup || true
	rm -rf bin dist
