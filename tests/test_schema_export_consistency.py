# -*- coding: utf-8 -*-
"""v1.14.14: JSON Schema 与实际导出必须严格一致。

背景: 全仓从来没有对导出的 JSON 做过 schema 校验, 于是漂移了两年没人发现 ——
schema/netpulse-result-v1.2.json 声明了 `duration_ms` / `selected_modules` /
`total_modules` 三个字段, `render_report_json` 却从不导出它们 (技术员拿不到
耗时与覆盖范围); 反过来导出里的 `site_check` / `site_note` / `meta_manual` /
`meta` 四个字段 schema 一个都没声明。schema 里又没设
`additionalProperties: false`, 所以即使拿标准校验器去验也不会报错。

本测试直接比对「schema 声明的字段集」与「实际导出的字段集」, 双向都不许有
多余/缺失; schema 未安装 `jsonschema` 时也能跑 (不依赖第三方包)。

运行: cd 到项目根目录, `python tests/test_schema_export_consistency.py`
"""
import json
import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netpulse as N  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(ROOT, "schema", "netpulse-result-v1.2.json")


def _report():
    N.LAST_RUN = {
        "app": "NetPulse", "version": N.APP_VERSION,
        "generated_at": datetime(2026, 1, 2, 3, 4, 5),
        "status": {"gateway": "正常", "dns": "警告"},
        "results": {
            "gateway": {"ping": {"loss_pct": 5.0, "avg_ms": 28.0,
                                 "jitter_ms": 12.0},
                        "issues": [{"severity": "警告", "message": "网关延迟偏高",
                                    "detail": "", "action": "检查网线"}]},
            "dns": {"servers": [{"server": "223.5.5.5", "avg_ms": 12.0,
                                 "loss_pct": 0}], "issues": []},
        },
        "keys": ["gateway", "dns"], "duration_ms": 12345, "total_modules": 23,
        "system": {"hostname": "PC-01", "local_ip": "192.168.1.10",
                   "gateway": "192.168.1.1", "dns": "223.5.5.5"},
    }
    diag = N.diagnose(N.LAST_RUN["results"])
    return N.build_report(diagnosis=diag.to_dict() if hasattr(diag, "to_dict")
                          else diag)


class TestSchemaExportConsistency(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.schema = json.load(open(SCHEMA_PATH, encoding="utf-8"))
        cls.doc = json.loads(N.render_report_json(_report()))

    def test_root_fields_both_ways(self):
        declared = set(self.schema["properties"])
        emitted = set(self.doc)
        self.assertEqual(
            emitted - declared, set(),
            "导出了 schema 未声明的字段 —— 消费方按 schema 写代码会漏读: %s"
            % sorted(emitted - declared))
        self.assertEqual(
            declared - emitted, set(),
            "schema 声明了但从不导出的字段 (文档在说谎): %s"
            % sorted(declared - emitted))

    def test_tech_fields_both_ways(self):
        declared = set(self.schema["properties"]["tech"]["properties"])
        emitted = set(self.doc["tech"])
        self.assertEqual(emitted - declared, set(),
                         "tech 内导出未声明字段: %s" % sorted(emitted - declared))
        self.assertEqual(declared - emitted, set(),
                         "tech 内声明但从不导出: %s" % sorted(declared - emitted))

    def test_schema_forbids_unknown_root_fields(self):
        """additionalProperties=false 才拦得住漂移; 没它即使有错也不会报。"""
        self.assertIs(self.schema.get("additionalProperties"), False)

    def test_required_fields_present(self):
        for k in self.schema["required"]:
            self.assertIn(k, self.doc, "必填字段缺失: %s" % k)

    def test_coverage_fields_have_real_values(self):
        """v1.14.14 补导出的三个字段必须是真值, 不是占位 0。"""
        self.assertEqual(self.doc["duration_ms"], 12345)
        self.assertEqual(self.doc["selected_modules"], 2)
        self.assertEqual(self.doc["total_modules"], 23)

    def test_declared_version_matches_app(self):
        self.assertEqual(self.doc["schema_version"], "1.2.0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
