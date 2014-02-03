
export PYTHONPATH=./

compile:
	@echo 'This method is not implemented' 

clean:
	@echo "rm -rf ./dist"; rm -rf ./dist
	@echo "rm -rf ./build"; rm -rf ./build
	@echo "rm -rf *.egg-info"; rm -rf *.egg-info

test:
	./tests/runTests

update:
	git pull
	git submodule update
	git submodule update --remote --force

