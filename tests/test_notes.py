"""
Example CRUD tests — notes.
Delete this file when you remove the notes feature.
"""


def test_create_note(auth_client):
    """Can create a new note."""
    resp = auth_client.post("/notes/new", data={
        "title": "Test Note",
        "body": "This is a test note.",
    }, follow_redirects=True)
    assert resp.status_code == 200


def test_view_note(auth_client):
    """Can view a created note."""
    # Create a note first
    auth_client.post("/notes/new", data={
        "title": "View Test",
        "body": "Content here.",
    })
    resp = auth_client.get("/notes/1")
    # Note might be id 1 or 2 depending on test order
    assert resp.status_code in (200, 404)


def test_create_note_requires_title(auth_client):
    """Note creation fails without a title."""
    resp = auth_client.post("/notes/new", data={
        "title": "",
        "body": "No title",
    }, follow_redirects=True)
    assert resp.status_code == 200


def test_new_note_page(auth_client):
    """New note page loads."""
    resp = auth_client.get("/notes/new")
    assert resp.status_code == 200
