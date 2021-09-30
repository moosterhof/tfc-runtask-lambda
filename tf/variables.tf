variable "region" {
  description = "The region where the resources are created."
  default     = "us-east-1"
}

variable "lambda_handler" {
  description = "The lambda binary"
  default     = "opa-handler"
}
