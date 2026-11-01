from dac.query_analysis import analyze, mask_strings, strip_comments


def test_strings_and_comments_do_not_leak_into_analysis():
    q = ('process where /* process.fake == "x" */ process.name : "a // not a comment" and\n'
         '// trailing comment with not user.name\n process.args : """C:\\raw\\"""')
    clean = strip_comments(q)
    assert "process.fake" not in clean and "a // not a comment" in clean and "user.name" not in clean
    masked, literals = mask_strings(clean)
    assert literals == ["a // not a comment", "C:\\raw\\"]
    assert analyze(q, "eql").fields == ["process.name", "process.args"]


def test_case_sensitive_ops_and_optional_fields():
    prof = analyze('process where process.name == "cmd.exe" and process.args like "-x" and '
                   'process.executable in ("a") and process.parent.name in~ ("b") and '
                   '?process.pe.original_file_name : "c"', "eql")
    ops = {(o.field, o.op) for o in prof.case_sensitive_ops}
    assert ops == {("process.name", "=="), ("process.args", "like"), ("process.executable", "in")}
    assert prof.optional_fields == {"process.pe.original_file_name"}


def test_sequence_profile():
    prof = analyze('sequence by host.id with maxspan=30s [process where true] [file where true]', "eql")
    assert prof.sequence.maxspan_seconds == 30 and prof.sequence.join_keys[0] == ["host.id"]
