.PHONY: all
all: build

.PHONY: local
local: opa

opa:
	go build

.PHONY: build
build: ../../bin/opa-handler

../../bin/opa-handler:
	env GOOS=linux GOARCH=amd64 go build -o ../../bin/opa-handler

.PHONY: clean
clean:
	rm -f ../../bin/opa-handler opa

# https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-using-invoke.html
.PHONY: test
test: opa
	./opa


# Invoking function with event file
# $ sam local invoke "Ratings" -e event.json

# Invoking function with event via stdin
# $ echo '{"message": "Hey, are you there?" }' | sam local invoke --event - "Ratings"

# For more options
# $ sam local invoke --help
