SINGBOX_TAGS := with_gvisor,with_quic,with_wireguard,with_openvpn,with_utls,badlinkname,tfogo_checklinkname0
SINGBOX_LDFLAGS := -checklinkname=0

.PHONY: build build-wails clean test test-integration run

build: build-wails

build-wails:
	./scripts/build_wails.sh

test:
	go test -tags '$(SINGBOX_TAGS)' -ldflags '$(SINGBOX_LDFLAGS)' ./internal/... ./cmd/crosslink-daemon -v

test-integration:
	go test -tags '$(SINGBOX_TAGS),integration' -ldflags '$(SINGBOX_LDFLAGS)' ./internal/... ./cmd/crosslink-daemon -v

clean:
	rm -rf build dist bin cmd/gui/assets cmd/gui/daemon cmd/gui/daemon_sha.go

run:
	wails3 dev
