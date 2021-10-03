.PHONY: all
all: build

.PHONY: local
local: auth

auth: main.go handler/handler.go
	go build

.PHONY: build
build: ../../bin/auth-handler

../../bin/auth-handler: main.go handler/handler.go
	env GOOS=linux GOARCH=amd64 go build -o ../../bin/auth-handler

.PHONY: clean
clean:
	rm -f ../../bin/auth-handler auth

# https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-using-invoke.html
.PHONY: test
test: auth
	./auth


# Invoking function with event file
# $ sam local invoke "Ratings" -e event.json

# Invoking function with event via stdin
# $ echo '{"message": "Hey, are you there?" }' | sam local invoke --event - "Ratings"

# For more options
# $ sam local invoke --help
