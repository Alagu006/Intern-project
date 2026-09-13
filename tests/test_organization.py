"""
Unit and integration tests for Folders and Tags organization.

Covers:
- Creating root folders and nested subfolders (POST /api/folders)
- Listing folders with optional parent_id filter (GET /api/folders)
- Retrieving folder details, subfolders, and files (GET /api/folders/<id>)
- Moving a file into a folder via PATCH /api/files/<id>
- Moving a file out of a folder back to root (folder_id=null)
- Filtering files by folder_id (GET /api/files?folder_id=...)
- Deleting a folder unsets files' folder_id to None while preserving files
- Creating and listing tags (POST/GET /api/tags)
- Tagging and untagging files (PATCH /api/files/<id>, POST/DELETE /api/files/<id>/tags)
- Filtering files by tag (GET /api/files?tag=...)
- Deleting a tag removes associations while preserving files
- Cross-user isolation: user cannot see, modify, or delete another user's folders/tags
"""

import io
import uuid
from app.models import File, Folder, Tag


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


class TestFolderManagement:
    """Tests for Folder CRUD and nesting."""

    def test_create_folder_success(self, client, owner_token):
        """Creating a folder returns 201 with folder details."""
        res = client.post(
            "/api/folders",
            json={"name": "Work Documents"},
            headers=auth_header(owner_token),
        )
        assert res.status_code == 201
        data = res.get_json()
        assert "folder" in data
        assert data["folder"]["name"] == "Work Documents"
        assert data["folder"]["parent_id"] is None
        assert "id" in data["folder"]

    def test_create_nested_subfolder_success(self, client, owner_token):
        """Creating a subfolder referencing a valid parent_id succeeds."""
        # 1. Parent folder
        res_p = client.post(
            "/api/folders",
            json={"name": "Parent Folder"},
            headers=auth_header(owner_token),
        )
        parent_id = res_p.get_json()["folder"]["id"]

        # 2. Child subfolder
        res_c = client.post(
            "/api/folders",
            json={"name": "Child Subfolder", "parent_id": parent_id},
            headers=auth_header(owner_token),
        )
        assert res_c.status_code == 201
        assert res_c.get_json()["folder"]["parent_id"] == parent_id

    def test_create_folder_empty_name_rejected(self, client, owner_token):
        """Creating a folder with empty name returns 400."""
        res = client.post(
            "/api/folders",
            json={"name": "   "},
            headers=auth_header(owner_token),
        )
        assert res.status_code == 400
        assert res.get_json()["error"] == "Folder name is required"

    def test_create_folder_invalid_parent_rejected(self, client, owner_token, recipient_token):
        """Creating a folder with non-existent or other user's parent_id fails."""
        # Bad UUID
        res_bad = client.post(
            "/api/folders",
            json={"name": "Sub", "parent_id": "not-a-uuid"},
            headers=auth_header(owner_token),
        )
        assert res_bad.status_code == 400

        # Non-existent UUID
        res_missing = client.post(
            "/api/folders",
            json={"name": "Sub", "parent_id": str(uuid.uuid4())},
            headers=auth_header(owner_token),
        )
        assert res_missing.status_code == 404

        # Recipient creates a folder
        res_rec = client.post(
            "/api/folders",
            json={"name": "Recipient Folder"},
            headers=auth_header(recipient_token),
        )
        rec_folder_id = res_rec.get_json()["folder"]["id"]

        # Owner tries to nest under recipient's folder -> 403
        res_hacked = client.post(
            "/api/folders",
            json={"name": "Owner Sub", "parent_id": rec_folder_id},
            headers=auth_header(owner_token),
        )
        assert res_hacked.status_code == 403

    def test_list_folders_and_parent_filtering(self, client, owner_token, recipient_token):
        """Listing folders respects owner isolation and parent_id filtering."""
        # Owner creates Root1, Root2, and Sub1 (under Root1)
        res_r1 = client.post("/api/folders", json={"name": "Root A"}, headers=auth_header(owner_token))
        r1_id = res_r1.get_json()["folder"]["id"]

        client.post("/api/folders", json={"name": "Root B"}, headers=auth_header(owner_token))
        client.post("/api/folders", json={"name": "Sub of A", "parent_id": r1_id}, headers=auth_header(owner_token))

        # Recipient creates a folder
        client.post("/api/folders", json={"name": "Recipient Root"}, headers=auth_header(recipient_token))

        # Owner lists all folders -> receives exactly 3 folders
        res_all = client.get("/api/folders", headers=auth_header(owner_token))
        assert res_all.status_code == 200
        assert len(res_all.get_json()["folders"]) == 3

        # Owner filters by parent_id=root -> receives Root A and Root B (2 folders)
        res_root = client.get("/api/folders?parent_id=root", headers=auth_header(owner_token))
        assert res_root.status_code == 200
        root_folders = res_root.get_json()["folders"]
        assert len(root_folders) == 2
        assert all(f["parent_id"] is None for f in root_folders)

        # Owner filters by parent_id=r1_id -> receives Sub of A (1 folder)
        res_sub = client.get(f"/api/folders?parent_id={r1_id}", headers=auth_header(owner_token))
        assert res_sub.status_code == 200
        assert len(res_sub.get_json()["folders"]) == 1
        assert res_sub.get_json()["folders"][0]["name"] == "Sub of A"

    def test_get_folder_details_with_contents(self, client, owner_token):
        """GET /api/folders/<id> returns folder details, subfolders, and files."""
        res_p = client.post("/api/folders", json={"name": "Project X"}, headers=auth_header(owner_token))
        p_id = res_p.get_json()["folder"]["id"]

        # Subfolder
        client.post("/api/folders", json={"name": "Specs", "parent_id": p_id}, headers=auth_header(owner_token))

        # Upload file directly into folder
        client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"spec contents"), "spec.pdf"), "folder_id": p_id},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )

        res_detail = client.get(f"/api/folders/{p_id}", headers=auth_header(owner_token))
        assert res_detail.status_code == 200
        data = res_detail.get_json()
        assert data["folder"]["name"] == "Project X"
        assert len(data["subfolders"]) == 1
        assert data["subfolders"][0]["name"] == "Specs"
        assert len(data["files"]) == 1
        assert data["files"][0]["filename"] == "spec.pdf"


class TestFileFolderMovementAndFiltering:
    """Tests for moving files into/out of folders and filtering file listings."""

    def test_move_file_into_folder_and_back_to_root(self, client, owner_token, app, db):
        """A file can be moved into a folder via PATCH, and moved back to root with folder_id=null."""
        # 1. Create a folder
        res_f = client.post("/api/folders", json={"name": "Archive"}, headers=auth_header(owner_token))
        folder_id = res_f.get_json()["folder"]["id"]

        # 2. Upload file at root
        res_file = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"financial report"), "finance.xlsx")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res_file.get_json()["file"]["id"]
        assert res_file.get_json()["file"]["folder_id"] is None

        # 3. Move file into folder via PATCH
        res_patch = client.patch(
            f"/api/files/{file_id}",
            json={"folder_id": folder_id},
            headers=auth_header(owner_token),
        )
        assert res_patch.status_code == 200
        assert res_patch.get_json()["file"]["folder_id"] == folder_id

        # 4. Filter files by folder_id -> returns this file
        res_filter = client.get(f"/api/files?folder_id={folder_id}", headers=auth_header(owner_token))
        assert res_filter.status_code == 200
        assert len(res_filter.get_json()["files"]) == 1
        assert res_filter.get_json()["files"][0]["id"] == file_id

        # Filter by root -> returns 0 files
        res_root = client.get("/api/files?folder_id=root", headers=auth_header(owner_token))
        assert res_root.status_code == 200
        assert len(res_root.get_json()["files"]) == 0

        # 5. Move file back to root
        res_unmove = client.patch(
            f"/api/files/{file_id}",
            json={"folder_id": None},
            headers=auth_header(owner_token),
        )
        assert res_unmove.status_code == 200
        assert res_unmove.get_json()["file"]["folder_id"] is None

        # Now filter by root returns 1 file
        res_root2 = client.get("/api/files?folder_id=root", headers=auth_header(owner_token))
        assert len(res_root2.get_json()["files"]) == 1

    def test_delete_folder_preserves_files_by_unsetting_folder_id(self, client, owner_token, app, db):
        """Deleting a folder unsets folder_id to None on all contained files without deleting them."""
        res_f = client.post("/api/folders", json={"name": "Temp Folder"}, headers=auth_header(owner_token))
        folder_id = res_f.get_json()["folder"]["id"]

        # Upload file in folder
        res_file = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"preserved file"), "data.csv"), "folder_id": folder_id},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res_file.get_json()["file"]["id"]

        # Delete folder
        res_del = client.delete(f"/api/folders/{folder_id}", headers=auth_header(owner_token))
        assert res_del.status_code == 200

        # File is still in database and moved to root (folder_id=None)
        with app.app_context():
            file_rec = db.session.get(File, uuid.UUID(file_id))
            assert file_rec is not None
            assert file_rec.folder_id is None


class TestTagManagementAndFiltering:
    """Tests for Tag CRUD, tagging files, and tag-based file filtering."""

    def test_create_and_list_tags(self, client, owner_token, recipient_token):
        """Creating and listing tags is owner-isolated and idempotent."""
        res1 = client.post("/api/tags", json={"name": "tax"}, headers=auth_header(owner_token))
        assert res1.status_code == 201
        assert res1.get_json()["tag"]["name"] == "tax"

        # Idempotent re-creation
        res2 = client.post("/api/tags", json={"name": "tax"}, headers=auth_header(owner_token))
        assert res2.status_code in (200, 201)
        assert res2.get_json()["tag"]["name"] == "tax"

        # Empty name rejected
        res_bad = client.post("/api/tags", json={"name": " "}, headers=auth_header(owner_token))
        assert res_bad.status_code == 400

        # List tags
        res_list = client.get("/api/tags", headers=auth_header(owner_token))
        assert res_list.status_code == 200
        assert len(res_list.get_json()["tags"]) == 1

        # Recipient sees 0 tags
        res_rec = client.get("/api/tags", headers=auth_header(recipient_token))
        assert len(res_rec.get_json()["tags"]) == 0

    def test_tag_file_via_patch_and_filter(self, client, owner_token):
        """Attaching tags to files via PATCH and filtering files by ?tag=."""
        # 1. Upload two files
        res1 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"invoice 1"), "inv1.pdf")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        f1_id = res1.get_json()["file"]["id"]

        res2 = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"contract 1"), "contract.pdf")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        f2_id = res2.get_json()["file"]["id"]

        # 2. Tag f1 with 'finance' and 'q4'
        res_tag1 = client.patch(
            f"/api/files/{f1_id}",
            json={"tags": ["finance", "q4"]},
            headers=auth_header(owner_token),
        )
        assert res_tag1.status_code == 200
        assert set(res_tag1.get_json()["file"]["tags"]) == {"finance", "q4"}

        # Tag f2 with 'legal'
        client.patch(
            f"/api/files/{f2_id}",
            json={"tags": ["legal"]},
            headers=auth_header(owner_token),
        )

        # 3. Filter files by ?tag=finance -> returns only f1
        res_filter = client.get("/api/files?tag=finance", headers=auth_header(owner_token))
        assert res_filter.status_code == 200
        assert len(res_filter.get_json()["files"]) == 1
        assert res_filter.get_json()["files"][0]["id"] == f1_id

        # 4. Filter files by ?tag=legal -> returns only f2
        res_filter_legal = client.get("/api/files?tag=legal", headers=auth_header(owner_token))
        assert len(res_filter_legal.get_json()["files"]) == 1
        assert res_filter_legal.get_json()["files"][0]["id"] == f2_id

        # 5. Filter files by non-existent tag -> returns 0 files
        res_filter_none = client.get("/api/files?tag=marketing", headers=auth_header(owner_token))
        assert len(res_filter_none.get_json()["files"]) == 0

    def test_add_and_remove_file_tags_dedicated_endpoints(self, client, owner_token):
        """Attaching tags via POST /api/files/<id>/tags and removing via DELETE."""
        res_file = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"document"), "doc.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res_file.get_json()["file"]["id"]

        # Add tag 'confidential'
        res_add = client.post(
            f"/api/files/{file_id}/tags",
            json={"name": "confidential"},
            headers=auth_header(owner_token),
        )
        assert res_add.status_code == 200
        assert "confidential" in res_add.get_json()["file"]["tags"]

        # Remove tag 'confidential'
        res_rem = client.delete(
            f"/api/files/{file_id}/tags/confidential",
            headers=auth_header(owner_token),
        )
        assert res_rem.status_code == 200
        assert "confidential" not in res_rem.get_json()["file"]["tags"]

    def test_delete_tag_removes_associations(self, client, owner_token, app, db):
        """Deleting a tag via DELETE /api/tags/<id> removes associations and leaves file intact."""
        res_tag = client.post("/api/tags", json={"name": "to-delete"}, headers=auth_header(owner_token))
        tag_id = res_tag.get_json()["tag"]["id"]

        res_file = client.post(
            "/api/files",
            data={"file": (io.BytesIO(b"content"), "keep.txt")},
            headers=auth_header(owner_token),
            content_type="multipart/form-data",
        )
        file_id = res_file.get_json()["file"]["id"]

        # Associate tag
        client.patch(f"/api/files/{file_id}", json={"tags": ["to-delete"]}, headers=auth_header(owner_token))

        # Delete tag
        res_del = client.delete(f"/api/tags/{tag_id}", headers=auth_header(owner_token))
        assert res_del.status_code == 200

        # File is intact, tag is gone
        with app.app_context():
            file_rec = db.session.get(File, uuid.UUID(file_id))
            assert file_rec is not None
            assert len(file_rec.tags) == 0
