# Contributing

Issues and focused pull requests are welcome, especially for target adapters,
realistic isolation regressions, and false-positive tests.

Before opening a pull request:

```bash
make test
make vet
make build
```

Changes to a detector should include both a positive case and a no-leak control.
Changes to an adapter should prove that distinct tenant credentials are used and
that missing credentials fail closed. Keep the project focused on cross-tenant
isolation rather than general-purpose LLM safety testing.
