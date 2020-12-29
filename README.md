# Extractor karton service

Performs extraction of known archive types and e-mail attachments. Produces "raw" artifacts for further classification.

**Author**: CERT.pl

**Maintainers**: psrok1, nazywam, msm

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


## Usage

First of all, make sure you have setup the core system: https://github.com/CERT-Polska/karton

Then install karton-archive-extractor from PyPi:

```shell
$ pip install karton-archive-extractor

$ karton-archive-extractor
```

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/wp-content/uploads/2019/02/en_horizontal_cef_logo-1.png)
