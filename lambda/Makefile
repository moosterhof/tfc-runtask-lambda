all: go

go:
	go build

# https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-using-invoke.html
test:
	./tfruntask-lambda-opa


# Invoking function with event file
# $ sam local invoke "Ratings" -e event.json

# Invoking function with event via stdin
# $ echo '{"message": "Hey, are you there?" }' | sam local invoke --event - "Ratings"

# For more options
# $ sam local invoke --help


# nix-env -i nix-env -i aws-sam-cli
#
