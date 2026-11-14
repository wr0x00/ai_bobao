"""test_llm_stream.py —— LLM 流式层的回归测试

field_so_far 是 agent 思考/答复与环境方案实时播报的核心：从半截 JSON 里
增量抠字符串字段值。它一旦解析错，前端要么看不到字、要么看到乱码；
钉住转义、截断、非单调增长这些边界。
"""
import json

from llm import field_so_far


def test_complete_json_both_fields():
    raw = '{"thought": "先查环境", "final": "共 2 个环境"}'
    assert field_so_far(raw, "thought") == "先查环境"
    assert field_so_far(raw, "final") == "共 2 个环境"


def test_partial_json_grows():
    """流式的本质：JSON 没闭合也能读到已生成的部分。"""
    assert field_so_far('{"thought": "先查', "thought") == "先查"
    assert field_so_far('{"thought": "', "thought") == ""


def test_escapes_decoded():
    raw = '{"thought": "带\\n换行和\\"引号\\""}'
    assert field_so_far(raw, "thought") == '带\n换行和"引号"'


def test_unicode_escape():
    assert field_so_far('{"thought": "\\u4f60\\u597d"}', "thought") == "你好"


def test_truncated_escape_holds_tail():
    """尾部转义没写完：已生成的部分照常返回，残缺的转义等下一片。"""
    assert field_so_far('{"thought": "unfinished\\', "thought") == "unfinished"
    assert field_so_far('{"thought": "unfinished\\u2', "thought") == "unfinished"


def test_missing_or_malformed_returns_empty():
    assert field_so_far('{"other": 1}', "thought") == ""
    assert field_so_far('{"thought":}', "thought") == ""
    assert field_so_far("", "thought") == ""
    assert field_so_far("not json at all", "thought") == ""


def test_value_not_string():
    """值还没开始（冒号后是别的）或干脆是数字，不硬抠。"""
    assert field_so_far('{"thought": 123}', "thought") == ""
    assert field_so_far('{"thought":', "thought") == ""


def test_monotonic_growth_over_stream():
    """逐字流式喂入时，值只增不减且最终等于完整解析值。"""
    want = "思考内容abc"
    full = json.dumps({"thought": want, "final": "答复xyz"}, ensure_ascii=False)
    prev = ""
    for i in range(1, len(full) + 1):
        got = field_so_far(full[:i], "thought")
        if got:
            assert got.startswith(prev)
            prev = got
    assert prev == want
