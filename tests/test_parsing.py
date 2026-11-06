"""JSON extraction, chunking, normalization and dedup (pure functions)."""

from __future__ import annotations

from scanner.analyzer import (
    canonical_cwe,
    chunk_text,
    dedupe_findings,
    extract_json,
    group_log_hotspots,
    locate_snippet,
    normalize_severity,
)


class TestExtractJson:
    def test_plain(self):
        assert extract_json('{"a": 1}') == {"a": 1}

    def test_surrounding_prose(self):
        assert extract_json('Sure!\n{"findings": []}\nHope this helps.') == {"findings": []}

    def test_markdown_fence(self):
        assert extract_json('```json\n{"x": [1, 2]}\n```') == {"x": [1, 2]}

    def test_trailing_comma(self):
        assert extract_json('{"x": [1, 2,],}') == {"x": [1, 2]}

    def test_truncated_response_salvages_complete_items(self):
        data = extract_json('{"findings": [{"title": "A", "line": 1}, {"title": "B", "line": 2}, {"title": "C", "snip')
        assert [f["title"] for f in data["findings"]] == ["A", "B"]
        assert data["_truncated"] is True

    def test_garbage(self):
        assert extract_json("no json here") is None
        assert extract_json("") is None
        assert extract_json('{"findings": [{"title": "cut') is None


class TestChunking:
    def test_small_file_single_chunk(self):
        chunks = chunk_text("a\nb\n")
        assert len(chunks) == 1 and chunks[0].start_line == 1

    def test_large_file_overlaps_and_covers(self):
        text = "".join(f"line {i:05d} " + "x" * 60 + "\n" for i in range(400))  # ~28k chars
        chunks = chunk_text(text, size=6000, overlap=500)
        assert len(chunks) > 4
        lines = text.splitlines()
        for c in chunks:
            assert len(c.text) <= 6000
            assert lines[c.start_line - 1] == c.text.splitlines()[0]
        for a, b in zip(chunks, chunks[1:], strict=False):
            assert b.start_line < a.start_line + a.text.count("\n")  # overlap
        assert text.endswith(chunks[-1].text)


class TestNormalization:
    def test_severity(self):
        assert normalize_severity("CRITICAL") == "critical"
        assert normalize_severity("Moderate") == "medium"
        assert normalize_severity("weird") == "medium"

    def test_canonical_cwe_prefers_specific_concepts(self):
        assert canonical_cwe("OS Command Injection", "CWE-89") == "CWE-78"
        assert canonical_cwe("Insecure deserialization leading to code execution", "CWE-94") == "CWE-502"
        assert canonical_cwe("Hardcoded JWT secret", "CWE-347") == "CWE-798"
        assert canonical_cwe("Something unusual", "CWE-123") == "CWE-123"

    def test_locate_snippet_corrects_and_bounds_lines(self):
        lines = ["import os", "x = 1", "result = eval(expr)", "y = 2"]
        assert locate_snippet(lines, "result = eval(expr)", 40) == 3
        assert locate_snippet(lines, "not present", 2) == 2
        assert locate_snippet(lines, "not present", 99) is None  # out-of-range line discarded


class TestDedupe:
    def f(self, title, snippet, sev, line=1, cwe="CWE-89"):
        return {"file": "a.py", "title": title, "snippet": snippet, "severity": sev, "line": line, "cwe": cwe}

    def test_keeps_most_severe_and_merges_by_title_snippet(self):
        out = dedupe_findings([
            self.f("SQL Injection", "cur.execute(q)", "medium"),
            self.f("sql  injection", "cur.execute(q) ", "high"),
            self.f("Eval", "eval(x)", "critical", line=5, cwe="CWE-95"),
        ])
        assert len(out) == 2
        assert out[0]["title"] == "Eval"
        assert out[1]["severity"] == "high"

    def test_merges_same_line_and_cwe_with_different_titles(self):
        out = dedupe_findings([
            self.f("SQL Injection", "q = a + b", "high", line=7),
            self.f("Unsanitized SQL query", "cur.execute(q)", "medium", line=7),
        ])
        assert len(out) == 1


def test_log_grouping_by_source():
    lines = [
        "Oct 1 sshd[1]: Accepted publickey for deploy from 10.0.0.5 port 1 ssh2",
        "Oct 1 sshd[2]: Failed password for root from 6.6.6.6 port 2 ssh2",
        "Oct 1 sshd[3]: Accepted password for root from 6.6.6.6 port 3 ssh2",
        '7.7.7.7 - - [x] "GET /dl?file=../../etc/passwd HTTP/1.1" 200 10 "-" "-"',
    ]
    groups = {(name, src): nums for name, src, nums in group_log_hotspots(lines)}
    assert not any(src == "10.0.0.5" for _, src in groups)  # benign login without failures
    success = next(v for (n, s), v in groups.items() if s == "6.6.6.6" and "successful" in n)
    assert success == [2, 3]
    assert any(s == "7.7.7.7" and "traversal" in n for n, s in groups)
