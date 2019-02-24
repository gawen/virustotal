# virustotal

``virustotal`` is a Python module to use the [Virustotal](https://www.virustotal.com/) public API, a free service that analyzes files from malwares.

## Prerequisites

You need to get an API key to use the VirusTotal Public API 2.0. To do so, just [sign-up on the service](https://www.virustotal.com/), go to your profile and click on ``API Key``.

## How to use

### Install

Install ``virustotal`` using setuptools' related softwares.
    
    pip install virustotal
    easy_install virustotal

or clone this repos
    
    git clone git://github.com/Gawen/virustotal.git
    cd virustotal
    python setup.py install

### Import

Import the ``virustotal`` module

    import virustotal

Instantiate the handler's class.

    v = virustotal.VirusTotal(YOUR_API_KEY)

### Get a report

Use the method ``get()``. Its first parameter can be :

- A list of hashes (MD5, SHA1, SHA256) - returns a list of reports
- A hash (MD5, SHA1, SHA256)
- A scan-id (VirusTotal's scan UID)
- A file object (file, socket, StringIO)
- A file path or URL

For example,

    # Filepath
    report = v.get("/foo/bar")
    
    # EICAR (see Links section)
    report = v.get(StringIO.StringIO("X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"))

    # EICAR's MD5 (see Links section)
    report = v.get("44D88612FEA8A8F36DE82E1278ABB02F")

    # Multihash - Makes a batch request so it saves on your API request limit, returns a list of reports
    report_list = v.get(["100b471f6735e4a7d736c7e371289af8","0a624a3caf4fe3ccd7ef83412bc9d155","b644800a0cc59363ba7b51699f9ac20e"])

### Scan a file

Use the method ``scan()``. Its first parameter can be :

- A file object (file, socket, StringIO)
- A file path or URL

For example,

    # Filepath
    report = v.scan("/foo/bar")

    # EICAR (see Links section)
    report = v.scan(StringIO.StringIO("X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"))

You can set its parameter ``reanalyze`` to force VirusTotal to re-scan the file.

    # Force to re-scan EICAR (see Links section)
    report = v.scan(StringIO.StringIO("X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"), reanalyze = True)


### Report object

A report (instance of ``Report``) is returned by the method ``get()`` and ``scan()``.

During a scan, the final report is not returned immediatly because VirusTotal needs time to send you the results. You can know if a report is done using the parameter ``done``.

    if report.done:
        # Read the report

You can wait for the report to be done using the ``join()`` method.

    # Wait for the report to be ready
    report.join()
    assert report.done == True

Then, you can use the report to get the results:

    print "Report"
    print "- Resource's UID:", report.id
    print "- Scan's UID:", report.scan_id
    print "- Permalink:", report.permalink
    print "- Resource's SHA1:", report.sha1
    print "- Resource's SHA256:", report.sha256
    print "- Resource's MD5:", report.md5
    print "- Resource's status:", report.status
    print "- Antivirus' total:", report.total
    print "- Antivirus's positives:", report.positives
    for antivirus, malware in report:
        if malware is not None:
            print
            print "Antivirus:", antivirus[0]
            print "Antivirus' version:", antivirus[1]
            print "Antivirus' update:", antivirus[2]
            print "Malware:", malware

### Use as a client CLI

You can use ``virustotal.py`` as a CLI program to get report or scan files in VirusTotal.

    usage: python virustotal.py (get|scan) [resource]

``resource`` can be:
- A hash (MD5, SHA1, SHA256)
- A scan-id (VirusTotal's scan UID)
- A file path or URL

To ask VirusTotal to get the EICAR file report (see Links section).

    python virustotal.py get 44D88612FEA8A8F36DE82E1278ABB02F

Or test if this repository is virus-free ;-)
    
    python virustotal.py scan *

## Links

- [Public API documentation](https://www.virustotal.com/documentation/public-api/)
- [EICAR test file](http://en.wikipedia.org/wiki/EICAR_test_file)

