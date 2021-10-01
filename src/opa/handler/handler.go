package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/json"
	//	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	//	"time"

	"github.com/aws/aws-lambda-go/events"
	//	"github.com/aws/aws-lambda-go/lambda"
	//        "github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/open-policy-agent/opa/ast"
	//	"github.com/open-policy-agent/opa/loader"
	//	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
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
	payload_version               int
	access_token                  string
	task_result_id                string
	task_result_enforcement_level string
	task_result_callback_url      string
	run_app_url                   string
	run_id                        string
	run_message                   string
	run_created_at                string
	run_created_by                string
	workspace_id                  string
	workspace_name                string
	workspace_app_url             string
	organization_name             string
	plan_json_api_url             string
	vcs_repo_url                  string
	vcs_branch                    string
	vcs_pull_request_url          string
	vcs_commit_url                string
}

func (l lambdaHandler) Run(ctx context.Context, request events.APIGatewayProxyRequest) (Response, error) {

	log.Print("OPA Lambda starting", request.Body)
	log.Print("Request body: ###", request.Body, "###")
	log.Print("Request headers: ###", request.Headers, "###")

	// this is the HMAC for the request, if available
	// case is like: X-Tfc-Event-Hook-Signature
	signature := request.Headers["X-Tfc-Event-Hook-Signature"]
	log.Print("HMAC header: ###", signature, "###")

	mac := hmac.New(sha512.New, []byte(l.hmacKey))
	mac.Write([]byte(request.Body))
	expectedMAC := mac.Sum(nil)
	match := hmac.Equal([]byte(signature), expectedMAC)

	if match {
		log.Print("VALID MAC")
	} else {
		log.Print("INCORRECT MAC")
	}

	/*
		we can get 2 types of POSTs, a test POST to test the handler, should return 200
		and a full test, both should return 200 or and one of 'pass/fail'
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

	var r TFCRunTask
	err = json.Unmarshal([]byte(request.Body), &r)
	if err != nil {
		log.Print("json decoding error: ", err)
	}

	log.Print("access token: " + r.access_token)
	log.Print("task_result_callback_url: " + r.task_result_callback_url)
	log.Print("plan_json_api_url: " + r.plan_json_api_url)

	if r.access_token == "test-token" {
		log.Print("Detected new run task registration through test request")
		return buildResponse(LambdaResponse{Message: "Test Request Accepted"})
	} else {
		log.Print("normal task accepted")
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
func tfcCallback(message string, pass bool, url string, token string) {

	//payload, err := json.Marshal(message)
	//if err != nil {
	//	log.Fatalln(err)
	//}

	var status string
	if pass {
		status = "passed"
	} else {
		status = "failed"
	}

	payload := "{ \"data\": { \"type\": \"task-results\", \"attributes\": { \"status\": \"" + status + "\", \"message\": \"" + string(message) + "\"} } }"

	resp, err := http.NewRequest("PATCH", url, strings.NewReader(payload))
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
