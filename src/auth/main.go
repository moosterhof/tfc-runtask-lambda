package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/moosterhof/tfc-runtask-opa-lambda/src/auth/handler"
)

func main() {
	handler := handler.Create()
	lambda.Start(handler.Run)
}
