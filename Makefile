
DOCKER_TAG=fuzzer-qemu

docker-build:
	docker build -t ${DOCKER_TAG} .

docker-run:
	docker run -v $(PWD)/src:/src -it ${DOCKER_TAG}
