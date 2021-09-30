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
	"strings"
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

type TFCRunTask struct {
	access_token             string
	task_result_callback_url string
	plan_json_api_url        string
}

func (l lambdaHandler) Run(ctx context.Context, request events.APIGatewayProxyRequest) (Response, error) {

	log.Print("Request body: ", request.Body)
	log.Print("Request headers: ", request.Headers)

	/*
		we can get 2 types of POSTs, a test POST to test the handler, should return 200
		and a full test, both should return 200 or and one off 'pass/fail'
		the test request body looks like this:
		   {
		       "payload_version": 1,
		       "access_token": "test-token",
		       "task_result_id": "taskrs-xxxxxxxxxxxxxxxx",
		       "task_result_enforcement_level": "test",
		       "task_result_callback_url": "https://app.terraform.io/api/v2/task-results/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/callback",
		       "run_app_url": "https://app.terraform.io/app/test-org/test-workspace/runs/run-xxxxxxxxxxxxxxxx",
		       "run_id": "run-xxxxxxxxxxxxxxxx",
		       "run_message": "Test run message",
		       "run_created_at": "2021-01-01T00:00:00.000Z",
		       "run_created_by": "test-user",
		       "workspace_id": "ws-xxxxxxxxxxxxxxxx",
		       "workspace_name": "test-workspace",
		       "workspace_app_url": "https://app.terraform.io/app/test-org/test-workspace",
		       "organization_name": "test-org",
		       "plan_json_api_url": "https://app.terraform.io/api/v2/plans/plan-xxxxxxxxxxxxxxxx/json-output",
		       "vcs_repo_url": "https://github.com/test-org/test-repo",
		       "vcs_branch": "main",
		       "vcs_pull_request_url": "https://github.com/test-org/test-repo/pull/1",
		       "vcs_commit_url": "https://github.com/test-org/test-repo/commit/1234567sha"
		   }
	*/

	// this is the HMAC for the request, if available
	hmac := request.Headers["x-tfc-event-hook-signature"]
	log.Print("HMAC header: ", hmac)

	// verify HMAC here
	//verify := verifyhmac(request.Body, hmac, hmacKey)
	// if error, return 500

	dec := json.NewDecoder(strings.NewReader(request.Body))
	//dec.DisallowUnknownFields()
	var r TFCRunTask
	err := dec.Decode(&r)
	if err != nil {
		log.Print("json decoding error: ", err)
	}

	if r.access_token == "test-token" {
		log.Print("Detected new run task registration through test request")
		return buildResponse(LambdaResponse{ Message: "Test Request Accepted", })
	}

	lambdaResponse := LambdaResponse{
		Message: "Hello " + fmt.Sprint(request.Body),
	}

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

func buildResponse(lambdaResponse LambdaResponse) (Response, error) {
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
