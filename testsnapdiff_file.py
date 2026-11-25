import tempfile
from pathlib import Path
import snapdiff
import testdb


def main() -> None:
    testdb.init_db()
    actor = {"id": 1, "username": "eng_demo", "role": "engineer"}

    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp) / "sshd_config"

        # Baseline snapshot
        cfg.write_text("Port 22\nPermitRootLogin no\nMaxAuthTries 3\n", encoding="utf-8")
        s1 = snapdiff.capture_and_diff_snapshot(
            host_label="lab-host",
            snapshot_tag="base",
            target_path=str(cfg),
            actor=actor,
            allowed_roots=[Path(tmp)],
        )
        print("Baseline snapshot ID:", s1["id"], "| Has drift:", s1["has_drift"])

        # Modified config snapshot (adds 1 line, modifies 1 line in-place, removes 1 line)
        cfg.write_text("Port 2222\nPermitRootLogin no\nPasswordAuthentication no\n", encoding="utf-8")
        s2 = snapdiff.capture_and_diff_snapshot(
            host_label="lab-host",
            snapshot_tag="drift-1",
            target_path=str(cfg),
            actor=actor,
            allowed_roots=[Path(tmp)],
        )
        print(
            "Drift snapshot ID:",
            s2["id"],
            "| Added:",
            s2["added_count"],
            "| Modified:",
            s2["modified_count"],
            "| Removed:",
            s2["removed_count"],
        )

        # Clean up test snapshot rows so snaplens.db stays clean
        with testdb.get_connection() as conn:
            conn.execute("DELETE FROM snapshots WHERE id IN (?, ?)", (s1["id"], s2["id"]))
            conn.commit()
        print("Cleanup complete.")


if __name__ == "__main__":
    main()