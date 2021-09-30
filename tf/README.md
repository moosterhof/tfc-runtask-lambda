This contains generic Terraform infrastructure to create an API
Gateway that exposes a Lambda function for Terraform Run Tasks

Output are the URL and a randomized HMAC key that can be used for
signing and is passed to the Lambda as an environment variable
