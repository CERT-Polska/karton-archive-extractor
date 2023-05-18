# Extractor karton service

Performs extraction of known archive types and e-mail attachments. Produces "raw" artifacts for further classification.

**Author**: CERT.pl

**Maintainers**: psrok1, nazywam

**Consumes:**
```
{
    "type":  "sample",
    "stage": "recognized",
    "kind":  "archive"
    "payload": {
        "sample": <Resource>,
        "extraction_level": <int, default: 0>,
        "password": <archive password>,
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

In order to unpack all available formats you'll also need a few native dependencies that sflock relies on, the installation method recommended by sflock is:
```shell
RUN sed -i 's/ main/ main non-free/' /etc/apt/sources.list \
    && apt-get update && apt-get install -y \
    p7zip-full \
    rar \
    unace \
    cabextract \
    lzip
```

Then install karton-archive-extractor from PyPi:

```shell
$ pip install karton-archive-extractor

$ karton-archive-extractor
```

### Configuration

There are several configuration options you can tweak up to your liking.

```ini
[archive-extractor]
# Maximum levels of nested extraction
max_depth = 5
# Maximum unpacked child filesize, larger files are not reported
max_size = 26214400
# Maximum number of children files for further analysis
max_children = 1000
```

To learn more about configuring your karton services, take a look at [karton configuration docs](https://karton-core.readthedocs.io/en/latest/service_configuration.html)

## Running in Docker

Sflock uses [ZipJail](https://github.com/hatching/tracy/tree/master/src/zipjail) as a usermode syscall filtering mechanism. As a result, in our experience, container running the karton service has to have the `SYS_PTRACE` capability in order for the ptrace to execute correctly. Make sure it's enabled if you run into problems extracting certain archive types.

## Supported archive/compression formats*

```
.7z
.ace
.bup
.cab
.daa
.eml
.gz
.gzip
.iso
.lha
.lz
.lzh
.msg
.mso
.pdf
.rar
.tar
.tar.bz2
.tar.gz
.udf
.vhd
.vhdx
.xz
.zip
```

\* Assuming you are running Linux, please see the [sflock's readme](https://github.com/doomedraven/sflock/blob/master/README.md) for more information

## PE files debloating

Some malicious PE files contain intentionally added junk to make them too big for processing. Starting from v1.4.0, archive extractor 
supports optional debloating of these files, using [debloat tool made by Squiblydoo](https://github.com/Squiblydoo/debloat). 

`certpl/karton-archive-extractor` Docker image debloats PE files by default. To enable debloating in 
karton-archive-extractor installed from PyPI, you need to install additional extra dependencies:

```
pip install karton-archive-extractor[debloat]
```

---

![Co-financed by the Connecting Europe Facility by of the European Union](https://www.cert.pl/uploads/2019/02/en_horizontal_cef_logo-e1550495232540.png)
