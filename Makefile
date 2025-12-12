.PHONY: build
build:
	cd agent && go build -o ../bin/agent .

.PHONY: build-docker
build-docker:
	docker build -t hanshal785/drop-drop-agent:latest .

.PHONY: push-docker
push-docker:
	docker push hanshal785/drop-drop-agent:latest

.PHONY: clean
clean:
	rm -f bin/agent
