from fastapi.testclient import TestClient

import main

client = TestClient(main.app)


def test_app_exists():
    assert main.app is not None


def test_index_page():
    response = client.get("/", headers={"Host": "127.0.0.1"})
    assert response.status_code == 200
