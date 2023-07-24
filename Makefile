rebuild:
	cargo libbpf build
	cargo build
	sudo setcap cap_perfmon,cap_bpf+ep ./target/debug/certspook

debug:
	./target/debug/certspook

run:
	./target/release/certspook

clean:
	cargo clean

.PHONY: clean debug rebuild run
