# Tests - Samples and Validation

Unit tests, fixtures, and end-to-end checks for the shift-left toolchain.

## Structure

```
tests/
├── README.md
├── fixtures/                    # Test fixtures (non-secret)
│   ├── iac/
│   │   └── azure_storage_public.tf
│   └── docker/
│       └── Dockerfile.insecure
├── opa-tests/                   # OPA policy tests (rego)
└── e2e/                         # End-to-end tests
    ├── test-shift-left-all.sh
    └── test-pipeline-dev-prod.sh
```

## Usage

### End-to-end (shift-left toolchain)
```bash
bash tests/e2e/test-shift-left-all.sh
```

### OPA tests
```bash
make opa-test
```

### Dev/Prod policy behavior
```bash
bash tests/e2e/test-pipeline-dev-prod.sh
```

## Notes

- Fixtures are intentionally insecure and used for testing only.
- Do not use any fixture content in production.
