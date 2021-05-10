
DOCKER_TAG=fuzzer-qemu

docker-build:
	docker build -t ${DOCKER_TAG} .

docker-run:
	docker run -v $(PWD)/src:/src -it ${DOCKER_TAG}

persistent-hook:
	cd persistent_hook && \
	    cross build --target aarch64-unknown-linux-gnu && \
	    cd - &&\
	    cp persistent_hook/target/aarch64-unknown-linux-gnu/debug/libpersistent.so bin/
