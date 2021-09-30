output "api_url" {
  value = aws_api_gateway_stage.api.invoke_url
}

output "hmac_key" {
  value = local.hmac_key
}
