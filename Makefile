.PHONY: partA
partA:
	@python partA/run.py

.PHONY: fmt
fmt:
	@isort .

.PHONY: virtual
virtual:
	@virtualenv venv