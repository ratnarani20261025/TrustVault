import os, tempfile, unittest
from io import BytesIO
from app import app, db, init_db

class TrustVaultSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        app.config["TESTING"] = True
        self.db_path = os.path.join(self.tmp.name, "test.db")
        self.storage = os.path.join(self.tmp.name, "uploads")
        os.makedirs(self.storage)
        import app as module
        module.DB_PATH = self.db_path
        module.STORAGE = self.storage
        init_db()
        self.client = app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def login(self, username, password):
        page = self.client.get("/login")
        # CSRF token is present in the rendered form.
        import re
        token = re.search(rb'name="_csrf" value="([^"]+)"', page.data).group(1).decode()
        return self.client.post("/login", data={"_csrf":token,"username":username,"password":password}, follow_redirects=True)

    def test_unshared_document_denied(self):
        self.login("owner","OwnerDemo!2026")
        page = self.client.get("/upload")
        import re
        token = re.search(rb'name="_csrf" value="([^"]+)"', page.data).group(1).decode()
        self.client.post("/upload", data={"_csrf":token,"name":"secret","category":"HR",
                         "file":(BytesIO(b"private"),"secret.txt")}, content_type="multipart/form-data")
        with db() as con:
            doc = con.execute("SELECT id FROM documents WHERE name='secret'").fetchone()
        self.client.post("/logout", data={"_csrf":token})
        self.login("other","OtherDemo!2026")
        self.assertEqual(self.client.get("/document/"+doc["id"]).status_code,403)
        self.assertEqual(self.client.get("/document/"+doc["id"]+"/download").status_code,403)

    def test_viewer_cannot_upload(self):
        self.login("viewer","ViewerDemo!2026")
        self.assertEqual(self.client.get("/upload").status_code,403)

    def test_admin_audit_only(self):
        self.login("viewer","ViewerDemo!2026")
        self.assertEqual(self.client.get("/admin/audit").status_code,403)

if __name__ == "__main__":
    unittest.main()
