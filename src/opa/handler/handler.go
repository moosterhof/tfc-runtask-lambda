package handler

import (
	"bytes"
	"context"
	"encoding/json"
//	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
//	"github.com/aws/aws-lambda-go/lambda"
//        "github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/open-policy-agent/opa/ast"
//	"github.com/open-policy-agent/opa/loader"
//	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"io/ioutil"
	"log"
	"net/http"
//	"time"
)

var (
        err      error
        compiler *ast.Compiler
        store    storage.Store
        ctx      = context.Background()
)

type Response events.APIGatewayProxyResponse

// Handler - interface
type Handler interface {
	Run(ctx context.Context, event events.APIGatewayProxyRequest) (Response, error)
}

type lambdaHandler struct {
	hmacKey string
}

type LambdaResponse struct {
	Message string
}

func (l lambdaHandler) Run(ctx context.Context, event events.APIGatewayProxyRequest) (Response, error) {

	lambdaResponse := LambdaResponse{
		Message: "Hello " + fmt.Sprint(event),
	}
        log.Print("Request body: ", event)

	response, err := json.Marshal(lambdaResponse)

	res := Response{
		StatusCode:      200,
		IsBase64Encoded: false,
		Headers: map[string]string{
			"Access-Control-Allow-Origin":      "*",
			"Access-Control-Allow-Credentials": "true",
			"Cache-Control":                    "no-cache; no-store",
			"Content-Type":                     "application/json",
			"Content-Security-Policy":          "default-src self",
			"Strict-Transport-Security":        "max-age=31536000; includeSubDomains",
			"X-Content-Type-Options":           "nosniff",
			"X-XSS-Protection":                 "1; mode=block",
			"X-Frame-Options":                  "DENY",
		},
		Body: string(response),
	}

	return res, err
}

func init() {
/*
        policyData, err := loader.All([]string{"data"})
        if err != nil {
                log.Fatalf("Failed to load bundle from disk: %v", err)
        }

        // Compile the module. The keys are used as identifiers in error messages.
        compiler, err = policyData.Compiler()
        if err != nil {
                log.Fatalf("Failed to compile policies in bundle: %v", err)
        }

        store, err = policyData.Store()
        if err != nil {
                log.Fatalf("Failed to create storage from bundle: %v", err)
        }
*/
}

// This GET's additional information from TFC
func TFCget(url string) {

	resp, err := http.Get(url)
        // TODO: need token here?
	// resp.Header.Set("Authorization", "Bearer "+token)
	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println(string(body))

	return
}

// This PATCH'es the output back to TFC
func tfcCallback(message string, url string, token string) {

	payload, err := json.Marshal(message)
	if err != nil {
		log.Fatalln(err)
	}

	/*
	// payload needs to look like this:
        // status can be `passed` or `failed`
	{
	  "data": {
	    "type": "task-results",
	      "attributes": {
	        "status": "passed",
	        "message": "Hello task"
	      }
	  }
	}
	*/

	resp, err := http.NewRequest("PATCH", url, bytes.NewBuffer(payload))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Authorization", "Bearer "+token)

	if err != nil {
		log.Fatalln(err)
	}

	var result map[string]interface{}

	json.NewDecoder(resp.Body).Decode(&result)

	log.Println(result)
	log.Println(result["data"])
}

// NewLambdaHandler -
func NewLambdaHandler(
	hmacKey string,
) *lambdaHandler {
	return &lambdaHandler{
		hmacKey: hmacKey,
	}
}
