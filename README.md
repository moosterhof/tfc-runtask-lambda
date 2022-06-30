# Terraform Run Task validation through OPA through AWS Lambda

** Work in progress **

This repository utilizes the new Terraform Cloud Run Task mechanism
to perform a policy check through AWS Lambda as part of an apply
workflow.

https://www.hashicorp.com/blog/terraform-cloud-run-tasks-beta-now-available

https://www.terraform.io/docs/cloud/integrations/run-tasks/index.html#run-tasks-technology-partners

The Lambda handler is in src/handler
And the entire project can be deployed through a `terraform apply` in the `tf` directory.

It would be logical to use a Lambda Authorizer for authorization,
but these Lambda's do not receive the full request body. Hence the
authorization is built into the main lambda function.
