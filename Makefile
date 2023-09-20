
build:
	cargo libbpf build
	cargo build
	sudo setcap cap_sys_admin=ep ./target/debug/certspook

rebuild:
	make clean
	make build

debug:
	./target/debug/certspook

run:
	./target/release/certspook

clean:
	cargo clean

.PHONY: clean debug gen_activity rebuild run
