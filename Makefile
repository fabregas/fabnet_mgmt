
export PYTHONPATH=./

compile:
	@echo 'Usage:'
	@echo 'make clean'
	@echo 'make test'
	@echo 'make updeps'

clean:
	@echo "rm -rf ./dist"; rm -rf ./dist
	@echo "rm -rf ./build"; rm -rf ./build
	@echo "rm -rf *.egg-info"; rm -rf *.egg-info

test:
	./tests/runTests

updeps:
	git submodule update --remote --force

