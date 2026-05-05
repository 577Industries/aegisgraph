# Parser Wrapper Contract

Every parser wrapper must eventually expose a subprocess interface:

```json
{
  "input_id": "string",
  "input": "string",
  "timeout_ms": 1000
}
```

The wrapper returns a URL fact vector conforming to `schema/fact-vector.schema.json`, never performs network requests, and exits non-zero only on wrapper failure rather than parser disagreement.
