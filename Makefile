

test:
	opa eval --format pretty --data terraform.rego --input tfplan.json "data.terraform.analysis.authz"
