import os
import tempfile

import app


with tempfile.TemporaryDirectory() as tmp:
    old_out = app.OUT
    app.OUT = tmp
    job = "job123"
    os.makedirs(os.path.join(tmp, job))
    with open(os.path.join(tmp, job, "classes.dex"), "wb") as f:
        f.write(b"dex-test")
    with open(os.path.join(tmp, job, "unpacked.zip"), "wb") as f:
        f.write(b"zip-test")

    client = app.app.test_client()
    for name, expected in (("classes.dex", b"dex-test"), ("unpacked.zip", b"zip-test")):
        response = client.get(f"/download/{job}/{name}")
        assert response.status_code == 200, (name, response.status_code, response.data)
        assert response.data == expected
        assert "attachment" in response.headers.get("Content-Disposition", "")

    assert client.get(f"/download/{job}/../secret").status_code in (400, 404)
    assert client.get(f"/download/{job}/nested/file.dex").status_code in (400, 404)
    app.OUT = old_out

print("download route tests: PASS")
