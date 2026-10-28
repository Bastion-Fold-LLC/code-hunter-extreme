# Oracle — test & verification entrypoints.
#   make test          fast plumbing suite (pytest only; no benches, no model)
#   make benches-up    stand up + initialise the vulnerable recall benches
#   make benches-down  tear the benches down
#   make benches-check assert the benches are reachable
#   make e2e           run_all.py end-to-end layers (needs benches + local model)
#   make verify        THE GATE: model + benches + pytest + e2e, teardown always
.PHONY: test benches-up benches-down benches-check e2e verify

test:
	python3 -m pytest -q -p no:cacheprovider

benches-up:
	bash benches/bringup.sh up

benches-down:
	bash benches/bringup.sh down

benches-check:
	bash benches/bringup.sh check

e2e:
	python3 tests/run_all.py

verify:
	bash scripts/verify.sh
