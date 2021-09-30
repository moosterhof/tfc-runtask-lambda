package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/moosterhof/tf-runtask-opa-lambda/src/handler"
)

func main() {
	handler := handler.Create()
	lambda.Start(handler.Run)
}
