SUBDIRS := src/opa tf

.PHONY: all
all: $(SUBDIRS)

.PHONY: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

.PHONY: test
test:
	opa eval --format pretty --data terraform.rego --input tfplan.json "data.terraform.analysis.authz"
