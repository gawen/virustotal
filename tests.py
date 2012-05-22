import nose
import virustotal
import StringIO
import hashlib
import random

API_KEY = "22c6d056f1e99b8fb4fa6c2a811178723735e9840de18fa2df83fccfd21c95a0"
EICAR = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

EICAR_MD5 = hashlib.md5(EICAR).hexdigest()
EICAR_SHA1 = hashlib.sha1(EICAR).hexdigest()
EICAR_SHA256 = hashlib.sha256(EICAR).hexdigest()

RAND_STR = "".join(chr(random.randrange(256)) for i in range(1024))

v = virustotal.VirusTotal(API_KEY, 0)

### TESTS #####################################################################

def assert_eicar(report):
    assert report.md5 == EICAR_MD5
    assert report.sha1 == EICAR_SHA1
    assert report.sha256 == EICAR_SHA256
    assert report.positives > 0
 
def test_get_eicar_file():      assert_eicar(v.get(StringIO.StringIO(EICAR)))
def test_get_eicar_md5():       assert_eicar(v.get(EICAR_MD5))
def test_get_eicar_sha1():      assert_eicar(v.get(EICAR_SHA1))
def test_get_eicar_sha256():    assert_eicar(v.get(EICAR_SHA256))
def test_scan_eicar():
    r = v.scan(StringIO.StringIO(EICAR))
    r.join()
    assert_eicar(r)

def test_scan_eicar_force():
    r = v.scan(StringIO.StringIO(EICAR), reanalyze = True)
    r.join()
    assert_eicar(r)

def test_get_unknown_report():      assert v.get(StringIO.StringIO(RAND_STR)) is None
def test_get_unknown_report_hash(): assert v.get(hashlib.md5(RAND_STR).hexdigest()) is None

def test_entity_too_large():
    size = virustotal.FILE_SIZE_LIMIT + (1 * 1024 * 1024)
    entity_too_large = StringIO.StringIO(size * "a")
    try:
        r = v.scan(entity_too_large, reanalyze = True)

    except virustotal.VirusTotal.EntityTooLarge:
        return
    
    assert False, "Exception VirusTotal.EntityTooLarge should be raised."
