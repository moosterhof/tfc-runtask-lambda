package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/json"
	//	"errors"
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

type RequestBody struct {
	Payload_version               float64  `json:"payload_version"`
	Access_token                  string   `json:"access_token"`
	Task_result_id                string   `json:"task_result_id"`
	Task_result_enforcement_level string   `json:"task_result_enforcement_level"`
	Task_result_callback_url      string   `json:"task_result_callback_url"`
	Run_app_url                   string   `json:"run_app_url"`
	Run_id                        string   `json:"run_id"`
	Run_message                   string   `json:"run_message"`
	Run_created_at                string   `json:"run_created_at"`
	Run_created_by                string   `json:"run_created_by"`
	Workspace_id                  string   `json:"workspace_id"`
	Workspace_name                string   `json:"workspace_name"`
	Workspace_app_url             string   `json:"workspace_app_url"`
	Organization_name             string   `json:"organization_name"`
	Plan_json_api_url             string   `json:"plan_json_api_url"`
	Vcs_repo_url                  string   `json:"vcs_repo_url"`
	Vcs_branch                    string   `json:"vcs_branch"`
	Vcs_pull_request_url          string   `json:"vcs_pull_request_url"`
	Vcs_commit_url                string   `json:"vcs_commit_url"`
}

func (l lambdaHandler) Run(ctx context.Context, request events.APIGatewayProxyRequest) (Response, error) {

	log.Print("OPA Lambda starting")
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

	var r RequestBody
	err = json.Unmarshal([]byte(request.Body), &r)
	if err != nil {
		log.Print("json unmarshall error: ", err)
		return Response{Body: err.Error(), StatusCode: 500}, nil
	}

	log.Print("access token: " + r.Access_token)
	log.Print("task_result_callback_url: " + r.Task_result_callback_url)
	log.Print("plan_json_api_url: " + r.Plan_json_api_url)

	if r.Access_token == "test-token" {
		log.Print("Detected new run task registration through test request")
                // NO CHECK IS EXECUTED
		return buildResponse(LambdaResponse{Message: "Test Request Accepted"})
	}

        // ACTUAL CHECK HAPPENS HERE

        passed := true
        message := "testing 1 2 3"
        tfcCallback(message, passed, r.Task_result_callback_url, r.Access_token)

        return buildResponse(LambdaResponse{Message: "Request Accepted"})
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

	log.Print(string(body))

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

        log.Print("Payload: ###", payload, "###")
        log.Print("URL: ###", url, "###")
        log.Print("Token: ###", token, "###")

        client := &http.Client{}
	req, err := http.NewRequest("PATCH", url, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/vnd.api+json")
	req.Header.Set("Authorization", "Bearer "+token)

        log.Print("request: ###", req, "###")

        resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	var result map[string]interface{}

	json.NewDecoder(resp.Body).Decode(&result)

	log.Print(result)
	log.Print(result["data"])
}

// NewLambdaHandler -
func NewLambdaHandler(
	hmacKey string,
) *lambdaHandler {
	return &lambdaHandler{
		hmacKey: hmacKey,
	}
}
