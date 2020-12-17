# Extractor karton service

Performs extraction of known archive types and e-mail attachments. Produces "raw" artifacts for further classification.

Author: CERT.pl
Maintainers: psrok1, nazywam, msm

**Consumes:**
```
{
    "type":  "sample",
    "stage": "recognized",
    "kind":  "archive"
    "payload": {
        "sample": <Resource>,
        "extraction_level": <int, default: 0>,
    }
} 
```

**Produces:**
```
{
    "type": "sample",
    "kind": "raw",
    "payload": {
        "sample": <Resource>,
        "parent": <Resource>,
        "extraction_level": <int++>
    }
}
```
