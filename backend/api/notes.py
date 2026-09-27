"""
DFIR Workbench V2 - Analyst Notes & Evidence Board API Blueprint
Provides persistence for analyst notes, observations, and pinned items on the Evidence Board.
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge
from backend.models import AnalystNote, Bookmark

notes_bp = Blueprint("notes_bp", __name__)


# ---------------------------------------------------------------------------
# Analyst Notes Endpoints
# ---------------------------------------------------------------------------
@notes_bp.route("/api/v2/notes", methods=["GET"])
def list_notes():
    bridge = get_bridge()
    cid = request.args.get("case_id") or bridge.get_active_case_id()
    fid = request.args.get("finding_id")

    notes = bridge.db.list_analyst_notes(case_id=cid, finding_id=fid)
    return jsonify({
        "status": "success",
        "case_id": cid,
        "count": len(notes),
        "notes": [n.to_dict() for n in notes]
    })


@notes_bp.route("/api/v2/notes", methods=["POST"])
def add_note():
    bridge = get_bridge()
    data = request.get_json(silent=True) or {}
    cid = data.get("case_id") or bridge.get_active_case_id()
    if not cid:
        return jsonify({"status": "error", "error": "No active case specified"}), 400

    text = (data.get("text") or data.get("note") or data.get("note_text") or "").strip()
    if not text:
        return jsonify({"status": "error", "error": "Note text cannot be empty"}), 400

    note = AnalystNote(
        case_id=cid,
        entity_id=str(data.get("entity_id") or ""),
        entity_type=str(data.get("entity_type") or "general"),
        text=text,
        author=str(data.get("author") or "Analyst")
    )
    bridge.db.add_analyst_note(note)
    return jsonify({"status": "success", "note": note.to_dict()}), 201


@notes_bp.route("/api/v2/notes/<note_id>", methods=["DELETE"])
def delete_note(note_id):
    bridge = get_bridge()
    ok = bridge.db.delete_analyst_note(note_id)
    if not ok:
        return jsonify({"status": "error", "error": "Note not found or already deleted"}), 404
    return jsonify({"status": "success", "deleted_note_id": note_id})


# ---------------------------------------------------------------------------
# Evidence Board (Bookmarks) Endpoints
# ---------------------------------------------------------------------------
@notes_bp.route("/api/v2/board", methods=["GET"])
def list_board_items():
    bridge = get_bridge()
    cid = request.args.get("case_id") or bridge.get_active_case_id()
    items = bridge.db.list_bookmarks(case_id=cid)
    serialized = [b.to_dict() for b in items]
    return jsonify({
        "status": "success",
        "case_id": cid,
        "count": len(items),
        "items": serialized,
        "board_items": serialized
    })


@notes_bp.route("/api/v2/board", methods=["POST"])
def pin_board_item():
    bridge = get_bridge()
    data = request.get_json(silent=True) or {}
    cid = data.get("case_id") or bridge.get_active_case_id()
    if not cid:
        return jsonify({"status": "error", "error": "No active case specified"}), 400

    item_type = str(data.get("item_type") or data.get("entity_type") or "general")
    item_id = str(data.get("item_id") or data.get("entity_id") or "")
    notes = str(data.get("notes") or data.get("note") or "")

    bookmark = Bookmark(
        case_id=cid,
        item_type=item_type,
        item_id=item_id,
        notes=notes
    )
    bridge.db.create_bookmark(bookmark)
    b_dict = bookmark.to_dict()
    return jsonify({"status": "success", "item": b_dict, "board_item": b_dict}), 201


@notes_bp.route("/api/v2/board/<bookmark_id>", methods=["DELETE"])
def unpin_board_item(bookmark_id):
    bridge = get_bridge()
    ok = bridge.db.delete_bookmark(bookmark_id)
    if not ok:
        return jsonify({"status": "error", "error": "Board item not found"}), 404
    return jsonify({"status": "success", "deleted_id": bookmark_id})
