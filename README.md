# Terraform Run Task validation through OPA through AWS Lambda

** Work in progress **

This repository utilizes the new Terraform Cloud Run Task mechanism
to perform an OPA policy check in AWS Lambda as part of an apply
workflow.

https://www.hashicorp.com/blog/terraform-cloud-run-tasks-beta-now-available

https://www.terraform.io/docs/cloud/integrations/run-tasks/index.html#run-tasks-technology-partners

The Lambda handler is in src/handler
And the entire project can be deployed through a `terraform apply` in the `tf` directory.
