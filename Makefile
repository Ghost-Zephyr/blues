
export RUST_LOG = trace
CARGO := cargo
SU := doas

.PHONY: run debug release setcap

run: debug setcap
	target/debug/blues -t 1 recon -ro 3000 -p 1 -t 150 -l 1

nbd: debug setcap
	target/debug/blues nbd

debug:
	$(CARGO) build

release:
	$(CARGO) build --release

masscan: release setcap
	target/release/blues -t 48 recon -ro 7000 -p 48 -t 350 -l 420 # 69

setcap:
	test -d target/release && $(SU) setcap cap_net_raw+ep target/release/blues
	test -d target/debug && $(SU) setcap cap_net_raw+ep target/debug/blues

