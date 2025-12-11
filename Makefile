.PHONY: build
build:
	cd agent && go build -o ../bin/agent .

.PHONY: clean
clean:
	rm -f bin/agent
