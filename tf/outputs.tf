output "api_url" {
  value = "${aws_api_gateway_stage.stage.invoke_url}/${local.lambda_handler}"
}

output "hmac_key" {
  value = local.hmac_key
}
