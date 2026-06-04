"""Pytest plugin for test plan driven parametrization and result capture."""

from __future__ import annotations

import itertools
import importlib
import importlib.util
import inspect
import re
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml


_pytest_config = None
_repo_root = None


def _find_repo_root(config) -> Path:
    cwd = Path.cwd().resolve()
    if (cwd / "tests" / "testplan.yml").exists() or (cwd / "testplan.yml").exists():
        return cwd

    root = Path(str(config.rootpath)).resolve()
    if root == Path("/"):
        for parent in Path.cwd().resolve().parents:
            if (parent / "tests" / "testplan.yml").exists() or (parent / "testplan.yml").exists():
                return parent
        return Path.cwd().resolve()
    return root


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open() as fp:
        return yaml.safe_load(fp) or {}


def _testplan_config_path(config) -> Path:
    option = config.getoption("testplan_config")
    if option:
        return Path(option).resolve()
    tests_path = _repo_root / "tests" / "testplan.yml"
    if tests_path.exists():
        return tests_path
    return _repo_root / "testplan.yml"


def _testplan_doc_path(config) -> Path:
    option = config.getoption("testplan_doc")
    if option:
        return Path(option).resolve()
    return _repo_root / "doc" / "rst" / "testplan.rst"


def _get_plan(config) -> dict[str, Any]:
    plan = getattr(config, "_testplan_config", None)
    if plan is None:
        plan = _load_yaml(_testplan_config_path(config))
        config._testplan_config = plan
    return plan


def _get_testplan_id(item):
    marker = item.get_closest_marker("testplan")
    if marker and marker.args:
        return marker.args[0]
    return None


def _get_test_level(item):
    if item.get_closest_marker("smoke"):
        return "smoke"
    if item.get_closest_marker("default"):
        return "default"
    if item.get_closest_marker("extended"):
        return "extended"
    return "default"


def _get_callspec_params(item):
    callspec = getattr(item, "callspec", None)
    if not callspec:
        return {}
    return dict(callspec.params)


def _base_nodeid(nodeid):
    return re.sub(r"\[[^\]]*\]$", "", nodeid)


def _result_priority(outcome):
    return {
        "error": 4,
        "failed": 3,
        "skipped": 2,
        "passed": 1,
    }.get(outcome, 0)


def _result_label(outcome):
    return {
        "error": "ERROR",
        "failed": "FAILED",
        "passed": "PASSED",
        "skipped": "SKIPPED",
        "not-run": "NOT RUN",
    }.get(outcome, str(outcome).upper())


def _result_role(outcome):
    return "result-" + str(outcome).lower().replace("_", "-").replace(" ", "-")


def _result_badge(outcome):
    return f":{_result_role(outcome)}:`{_result_label(outcome)}`"


def _count_badge(outcome, count):
    if int(count) == 0:
        return f":testplan-count-zero:`{count}`"
    return f":testplan-count-{outcome}:`{count}`"


def _outcome_count_cells(counts, include_not_run=False):
    cells = [
        _count_badge("passed", counts.get("passed", 0)),
        _count_badge("failed", counts.get("failed", 0)),
        _count_badge("error", counts.get("error", 0)),
        _count_badge("skipped", counts.get("skipped", 0)),
    ]
    if include_not_run:
        cells.append(_count_badge("not-run", counts.get("not-run", 0)))
    return cells


def _need_link(need_id):
    escaped = _rst_escape(need_id)
    return f":need:`[[id]] <{escaped}>`"


def _merge_result(existing, new):
    if existing is None:
        return new
    if _result_priority(new["outcome"]) > _result_priority(existing["outcome"]):
        existing["outcome"] = new["outcome"]
    existing["duration"] += new["duration"]
    existing["cases"].extend(new["cases"])
    return existing


def _case_counts(cases):
    counts = {"total": 0, "passed": 0, "failed": 0, "error": 0, "skipped": 0}
    for case in cases:
        outcome = case.get("outcome", "")
        counts["total"] += 1
        if outcome in counts:
            counts[outcome] += 1
    return counts


def _result_param_names(plan, results):
    names = []
    for testplan_id in sorted(results):
        test_config = plan.get("tests", {}).get(testplan_id, {})
        for name, values in test_config.get("parameters", {}).items():
            if isinstance(values, list) and name not in names:
                names.append(name)
    for result in results.values():
        for case in result.get("cases", []):
            for name in case.get("params", {}):
                if name not in names:
                    names.append(name)
    return names


def _param_header(plan, name):
    return name


def _rst_escape(value):
    text = str(value).replace("\n", " ")
    return text.replace("`", "\\`")


def _rst_literal(value):
    text = _rst_escape(value)
    return f"``{text}``" if text else ""


def _result_summary(report):
    if report.longrepr is None:
        return ""
    return str(report.longrepr).splitlines()[-1]


def _test_params(plan, testplan_id):
    names, rows = _parameter_rows(plan, testplan_id)
    if not rows:
        return [], []
    ids = []
    for row in rows:
        ids.append("-".join(f"{name}-{value}" for name, value in row.items()))
    return names, [pytest.param(*(row[name] for name in names), id=ids[index]) for index, row in enumerate(rows)]


def _case_params(plan, testplan_id, case):
    params = dict(case.get("params", {}))
    _, rows = _parameter_rows(plan, testplan_id)
    for row in rows:
        if all(row.get(name) == value for name, value in params.items()):
            merged = dict(row)
            merged.update(params)
            return merged
    return params


def _parameter_rows(plan, testplan_id):
    tests = plan.get("tests", {})
    test_config = tests.get(testplan_id, {})
    parameters = test_config.get("parameters", {})
    names = [name for name, values in parameters.items() if isinstance(values, list)]
    if not names:
        return [], []
    value_sets = itertools.product(*(parameters[name] for name in names))
    return names, [dict(zip(names, values)) for values in value_sets]


def _parse_testplan_needs(testplan_path):
    parsed = {"tests": {}, "requirements": {}}
    if not testplan_path.exists():
        return parsed

    current = None
    for line in testplan_path.read_text().splitlines():
        match_directive = re.match(r"^\.\.\s+(test|req)::\s*(.*)$", line)
        if match_directive:
            if current and current.get("id"):
                parsed[current["collection"]][current["id"]] = current
            directive, title = match_directive.groups()
            current = {
                "collection": "tests" if directive == "test" else "requirements",
                "id": None,
                "title": title.strip(),
                "tags": [],
                "status": "",
                "verifies": [],
            }
            continue
        if current is None:
            continue
        if line.startswith(".. "):
            if current.get("id"):
                parsed[current["collection"]][current["id"]] = current
            current = None
            continue
        match = re.match(r"^\s+:(id|tags|status|verifies):\s*(.*)$", line)
        if not match:
            continue
        key, value = match.groups()
        if key in ("tags", "verifies"):
            current[key] = [tag.strip() for tag in value.split(",") if tag.strip()]
        else:
            current[key] = value.strip()

    if current and current.get("id"):
        parsed[current["collection"]][current["id"]] = current
    return parsed


def _parse_testplan_tests(testplan_path):
    return _parse_testplan_needs(testplan_path)["tests"]


def _validate_testplan_config(testplan_path, plan):
    authored_tests = set(_parse_testplan_tests(testplan_path))
    configured_tests = set(plan.get("tests", {}))
    missing = sorted(authored_tests - configured_tests)
    extra = sorted(configured_tests - authored_tests)
    errors = []
    if missing:
        errors.append("Authored test cases missing from testplan.yml: " + ", ".join(missing))
    if extra:
        errors.append("testplan.yml test cases missing from authored RST: " + ", ".join(extra))
    if errors:
        raise pytest.UsageError("\n".join(errors))


def _feature_summary(testplan_path, results):
    tests = _parse_testplan_tests(testplan_path)
    summary = {}
    for testplan_id, test in tests.items():
        outcome = results.get(testplan_id, {}).get("outcome", "not-run")
        cases = results.get(testplan_id, {}).get("cases", [])
        variant_counts = _case_counts(cases)
        for tag in test["tags"]:
            counts = summary.setdefault(
                tag,
                {
                    "test_cases": 0,
                    "variants": 0,
                    "passed": 0,
                    "failed": 0,
                    "error": 0,
                    "skipped": 0,
                    "not-run": 0,
                },
            )
            counts["test_cases"] += 1
            if cases:
                counts["variants"] += variant_counts["total"]
                counts["passed"] += variant_counts["passed"]
                counts["failed"] += variant_counts["failed"]
                counts["error"] += variant_counts["error"]
                counts["skipped"] += variant_counts["skipped"]
            else:
                counts["variants"] += 1
                counts[outcome if outcome in counts else "not-run"] += 1
    return summary


def _configured_variant_count(plan, testplan_id):
    _, rows = _parameter_rows(plan, testplan_id)
    return len(rows) if rows else 1


def _requirement_result(outcomes):
    if not outcomes:
        return "not-covered"
    worst = None
    for outcome in outcomes:
        if outcome == "not-covered":
            continue
        if worst is None or _result_priority(outcome) > _result_priority(worst):
            worst = outcome
    return worst or "not-run"


def _coverage_label(state):
    return {
        "covered": "COVERED",
        "partial": "PARTIAL",
        "planned": "PLANNED",
        "uncovered": "UNCOVERED",
    }.get(state, str(state).upper())


def _coverage_badge(state):
    return f":testplan-coverage-{state}:`{_coverage_label(state)}`"


def _requirement_coverage_summary(testplan_path, plan, results):
    parsed = _parse_testplan_needs(testplan_path)
    tests = parsed["tests"]
    requirements = parsed["requirements"]
    summary = []

    for req_id, requirement in sorted(requirements.items()):
        requirement_status = requirement.get("status", "supported") or "supported"
        linked_tests = [test_id for test_id, test in tests.items() if req_id in test.get("verifies", [])]
        counts = {"passed": 0, "failed": 0, "error": 0, "skipped": 0, "not-run": 0}
        outcomes = []
        configured_variants = 0
        executed_variants = 0

        if requirement_status == "unsupported":
            continue

        for test_id in linked_tests:
            configured_variants += _configured_variant_count(plan, test_id)
            result = results.get(test_id)
            if result:
                case_counts = _case_counts(result.get("cases", []))
                executed_variants += case_counts["total"]
                for outcome in ("passed", "failed", "error", "skipped"):
                    counts[outcome] += case_counts[outcome]
                    outcomes.extend([outcome] * case_counts[outcome])
                missing = max(_configured_variant_count(plan, test_id) - case_counts["total"], 0)
                counts["not-run"] += missing
                outcomes.extend(["not-run"] * missing)
            else:
                missing = _configured_variant_count(plan, test_id)
                counts["not-run"] += missing
                outcomes.extend(["not-run"] * missing)

        if not linked_tests:
            coverage = "uncovered"
            result = "not-covered"
        elif executed_variants == 0:
            coverage = "planned"
            result = "not-run"
        elif executed_variants < configured_variants or counts["not-run"]:
            coverage = "partial"
            result = _requirement_result(outcomes)
        else:
            coverage = "covered"
            result = _requirement_result(outcomes)

        summary.append(
            {
                "id": req_id,
                "title": requirement.get("title", ""),
                "coverage": coverage,
                "linked_tests": len(linked_tests),
                "variants": configured_variants,
                "result": result,
                **counts,
            }
        )
    return summary


def _append_requirement_coverage_table(lines, testplan_path, plan, results):
    requirement_summary = _requirement_coverage_summary(testplan_path, plan, results)
    if not requirement_summary:
        return
    lines += [
        "Requirement Coverage Summary",
        "============================",
        "",
        ".. list-table::",
        "   :class: testplan-summary-table",
        "   :header-rows: 1",
        "",
        "   * - Requirement",
        "     - Coverage",
        "     - Result",
        "     - Tests",
        "     - Variants",
        "     - Pass",
        "     - Fail",
        "     - Error",
        "     - Skip",
        "     - Not run",
    ]
    for item in requirement_summary:
        result = item["result"]
        if result == "not-covered":
            result_badge = ":result-not-run:`NOT COVERED`"
        else:
            result_badge = _result_badge(result)
        count_cells = _outcome_count_cells(item, include_not_run=True)
        lines += [
            f"   * - {_need_link(item['id'])}",
            f"     - {_coverage_badge(item['coverage'])}",
            f"     - {result_badge}",
            f"     - ``{item['linked_tests']}``",
            f"     - ``{item['variants']}``",
        ]
        lines.extend(f"     - {cell}" for cell in count_cells)
    lines.append("")


def _test_metadata(plan, testplan_id, config):
    tests = plan.get("tests", {})
    test_config = tests.get(testplan_id, {})
    params = test_config.get("parameters", {})
    metadata = {}
    pytest_mapping = getattr(config, "_testplan_pytest", {}).get(testplan_id)
    if pytest_mapping:
        metadata["pytest"] = pytest_mapping
        metadata["status"] = "implemented"
    else:
        metadata["status"] = "planned"
    for name, values in params.items():
        if isinstance(values, list):
            metadata[name] = ", ".join(str(value) for value in values)
        else:
            metadata[name] = str(values)
    return metadata


def _import_from_file(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _load_object(spec, config, test_config, testplan_id=None):
    module_spec, _, object_name = spec.partition("::")
    if not module_spec or not object_name:
        raise ValueError("sequence must use module::object or path.py::object syntax")

    root = _repo_root or _find_repo_root(config)
    extra_paths = [root]
    pytest_node = getattr(config, "_testplan_pytest", {}).get(testplan_id)
    if pytest_node:
        pytest_path = root / pytest_node.split("::", 1)[0]
        if pytest_path.exists():
            extra_paths.append(pytest_path.parent)

    added = []
    try:
        for path in extra_paths:
            path_str = str(path)
            if path_str not in sys.path:
                sys.path.insert(0, path_str)
                added.append(path_str)

        module_path = root / module_spec
        if module_spec.endswith(".py") or "/" in module_spec or "\\" in module_spec:
            module = _import_from_file(module_path, "_testplan_sequence_" + re.sub(r"\W+", "_", module_spec))
        else:
            module = importlib.import_module(module_spec)
        obj = module
        for part in object_name.split("."):
            obj = getattr(obj, part)
        return obj
    finally:
        for path_str in added:
            if path_str in sys.path:
                sys.path.remove(path_str)


def _call_sequence_builder(builder, params):
    signature = inspect.signature(builder)
    accepted = {}
    accepts_kwargs = any(param.kind == inspect.Parameter.VAR_KEYWORD for param in signature.parameters.values())
    for name, value in params.items():
        if accepts_kwargs or name in signature.parameters:
            accepted[name] = value
    if "table_mode" in signature.parameters and "table_mode" not in accepted:
        accepted["table_mode"] = None
    return builder(**accepted)


def _sequence_rows(plan, testplan_id, config):
    test_config = plan.get("tests", {}).get(testplan_id, {})
    sequence = test_config.get("sequence")
    if not sequence:
        return None, None
    _, rows = _parameter_rows(plan, testplan_id)
    params = rows[0] if rows else {}
    try:
        builder = _load_object(sequence, config, test_config, testplan_id)
        session = _call_sequence_builder(builder, params)
        if not hasattr(session, "_execution_table_rows"):
            return params, f"Sequence builder did not return an object with _execution_table_rows(): {sequence}"
        return params, session._execution_table_rows()
    except Exception as exc:  # Documentation generation should report, not hide, sequence issues.
        return params, f"Unable to render sequence {sequence}: {exc}"


def _write_sequence_tables(lines, plan, config):
    test_ids = [
        testplan_id
        for testplan_id, test_config in sorted(plan.get("tests", {}).items())
        if test_config.get("sequence")
    ]
    if not test_ids:
        return

    lines += [
        "Executable Sequences",
        "====================",
        "",
    ]
    for testplan_id in test_ids:
        params, rows_or_error = _sequence_rows(plan, testplan_id, config)
        lines += [
            f"``{testplan_id}``",
            "-" * (len(testplan_id) + 4),
            "",
        ]
        if params:
            param_text = ", ".join(f"{name}=``{_rst_escape(value)}``" for name, value in params.items())
            lines += [f"Representative variant: {param_text}", ""]
        if isinstance(rows_or_error, str):
            lines += [rows_or_error, ""]
            continue
        lines += [
            ".. list-table::",
            "   :class: testplan-summary-table",
            "   :header-rows: 1",
            "",
            "   * - Step",
            "     - Transaction",
            "     - Event",
            "     - Direction",
            "     - Address",
            "     - Data",
            "     - T/ACK",
            "     - Notes",
        ]
        for row in rows_or_error:
            lines += [
                f"   * - {_rst_literal(row.get('step', ''))}",
                f"     - {_rst_literal(row.get('transaction', ''))}",
                f"     - {_rst_literal(row.get('event', ''))}",
                f"     - {_rst_literal(row.get('direction', ''))}",
                f"     - {_rst_literal(row.get('address', ''))}",
                f"     - {_rst_literal(row.get('data', ''))}",
                f"     - {_rst_literal(row.get('tack', ''))}",
                f"     - {_rst_literal(row.get('notes', ''))}",
            ]
        lines.append("")


def _append_testplan_results(lines, plan, results, config):
    testplan_path = _testplan_doc_path(config)
    authored_tests = _parse_testplan_tests(testplan_path)

    test_ids = sorted(set(authored_tests) | set(plan.get("tests", {})) | set(results))
    for testplan_id in test_ids:
        metadata = _test_metadata(plan, testplan_id, config)
        result = results.get(testplan_id)
        lines.append(f".. needextend:: {testplan_id}")
        for field_name, value in metadata.items():
            lines.append(f"   :{field_name}: {value}")
        if result:
            lines += [
                f"   :result: {_result_label(result['outcome'])}",
            ]
        lines.append("")

    _append_requirement_coverage_table(lines, testplan_path, plan, results)

    if not results:
        lines += [
            "No pytest-linked test plan results have been captured yet.",
            "",
        ]
    else:
        lines += [
            "Test Case Result Summary",
            "========================",
            "",
            ".. list-table::",
            "   :class: testplan-summary-table",
            "   :header-rows: 1",
            "",
            "   * - Test case",
            "     - Result",
            "     - Variants",
            "     - Pass",
            "     - Fail",
            "     - Error",
            "     - Skip",
        ]
        for testplan_id in sorted(results):
            result = results[testplan_id]
            counts = _case_counts(result.get("cases", []))
            count_cells = _outcome_count_cells(counts)
            lines += [
                f"   * - ``{testplan_id}``",
                f"     - {_result_badge(result['outcome'])}",
                f"     - ``{counts['total']}``",
            ]
            lines.extend(f"     - {cell}" for cell in count_cells)
        lines.append("")

        lines += [
            "Test Case Timing Summary",
            "========================",
            "",
            ".. list-table::",
            "   :class: testplan-summary-table",
            "   :header-rows: 1",
            "",
            "   * - Test case",
            "     - Variants",
            "     - Duration (s)",
        ]
        for testplan_id in sorted(results):
            result = results[testplan_id]
            counts = _case_counts(result.get("cases", []))
            lines += [
                f"   * - ``{testplan_id}``",
                f"     - ``{counts['total']}``",
                f"     - ``{result['duration']:.3f}``",
            ]
        lines.append("")

        param_names = _result_param_names(plan, results)
        lines += [
            "Parameter Variant Results",
            "=========================",
            "",
            ".. list-table::",
            "   :class: testplan-summary-table",
            "   :header-rows: 1",
            "",
            "   * - Test plan ID",
            "     - Result",
        ]
        for name in param_names:
            lines.append(f"     - {_param_header(plan, name)}")
        lines += [
            "     - Duration (s)",
        ]

        for testplan_id in sorted(results):
            result = results[testplan_id]
            cases = sorted(result.get("cases", []), key=lambda case: case.get("nodeid", ""))
            for case in cases:
                case_params = _case_params(plan, testplan_id, case)
                lines += [
                    f"   * - ``{testplan_id}``",
                    f"     - {_result_badge(case['outcome'])}",
                ]
                for name in param_names:
                    value = case_params.get(name, "")
                    lines.append(f"     - {_rst_literal(value)}")
                lines += [
                    f"     - ``{case['duration']:.3f}``",
                ]
        lines.append("")

    summary = _feature_summary(testplan_path, results)
    if summary:
        lines += [
            "Feature Result Summary",
            "======================",
            "",
            ".. list-table::",
            "   :header-rows: 1",
            "",
            "   * - Feature",
            "     - Test cases",
            "     - Variants",
            "     - Pass",
            "     - Fail",
            "     - Error",
            "     - Skip",
            "     - Not run",
        ]
        for tag in sorted(summary):
            counts = summary[tag]
            count_cells = _outcome_count_cells(counts, include_not_run=True)
            lines += [
                f"   * - ``{tag}``",
                f"     - ``{counts['test_cases']}``",
                f"     - ``{counts['variants']}``",
            ]
            lines.extend(f"     - {cell}" for cell in count_cells)
        lines.append("")


def _append_testplan_details(lines, plan, config):
    lines += [
        "Test Details",
        "============",
        "",
    ]
    start_len = len(lines)
    _write_sequence_tables(lines, plan, config)
    if len(lines) == start_len:
        lines += [
            "No executable test details have been configured yet.",
            "",
        ]


def _write_testplan_report_rst(path, results, config):
    path.parent.mkdir(parents=True, exist_ok=True)
    plan = _get_plan(config)
    _validate_testplan_config(_testplan_doc_path(config), plan)
    lines = [
        ".. This file is generated by pytest --testplan-report-rst.",
        ".. Do not edit by hand.",
        "",
        ".. role:: result-passed",
        ".. role:: result-failed",
        ".. role:: result-error",
        ".. role:: result-skipped",
        ".. role:: result-not-run",
        ".. role:: testplan-count-passed",
        ".. role:: testplan-count-failed",
        ".. role:: testplan-count-error",
        ".. role:: testplan-count-skipped",
        ".. role:: testplan-count-not-run",
        ".. role:: testplan-count-zero",
        ".. role:: testplan-coverage-covered",
        ".. role:: testplan-coverage-partial",
        ".. role:: testplan-coverage-planned",
        ".. role:: testplan-coverage-uncovered",
        "",
    ]
    _append_testplan_results(lines, plan, results, config)
    _append_testplan_details(lines, plan, config)
    path.write_text("\n".join(lines))


def pytest_addoption(parser):
    parser.addoption(
        "--testplan-config",
        action="store",
        default=None,
        help="Path to central test plan YAML configuration",
    )
    parser.addoption(
        "--testplan-doc",
        action="store",
        default=None,
        help="Path to authored sphinx-needs test plan RST",
    )
    parser.addoption(
        "--testplan-report-rst",
        action="store",
        default=None,
        help="Write generated test plan report RST",
    )


def pytest_configure(config):
    global _pytest_config, _repo_root
    _pytest_config = config
    _repo_root = _find_repo_root(config)
    config.addinivalue_line("markers", "testplan(id): link test to a test plan ID")
    config._testplan_results = {}
    config._testplan_pytest = {}


def pytest_generate_tests(metafunc):
    marker = metafunc.definition.get_closest_marker("testplan")
    if not marker or not marker.args:
        return

    plan = _get_plan(metafunc.config)
    names, values = _test_params(plan, marker.args[0])
    if not names:
        return

    needed_names = [name for name in names if name in metafunc.fixturenames]
    if needed_names:
        indexes = [names.index(name) for name in needed_names]
        filtered_values = [pytest.param(*(param.values[index] for index in indexes), id=param.id) for param in values]
        metafunc.parametrize(needed_names, filtered_values)


def pytest_collection_modifyitems(config, items):
    plan = _get_plan(config)
    configured_tests = set(plan.get("tests", {}))
    pytest_mappings = {}
    errors = []

    for item in items:
        testplan_id = _get_testplan_id(item)
        if testplan_id:
            if testplan_id not in configured_tests:
                errors.append(f"{item.nodeid} uses unknown test plan ID {testplan_id}")
            base_nodeid = _base_nodeid(item.nodeid)
            existing = pytest_mappings.get(testplan_id)
            if existing and existing != base_nodeid:
                errors.append(
                    f"{testplan_id} is implemented by multiple pytest tests: {existing}, {base_nodeid}"
                )
            else:
                pytest_mappings[testplan_id] = base_nodeid
            item.user_properties.append(("testplan_id", testplan_id))
            item.user_properties.append(("testplan_level", _get_test_level(item)))
            item.user_properties.append(("testplan_params", _get_callspec_params(item)))

    if errors:
        raise pytest.UsageError("\n".join(errors))
    config._testplan_pytest = pytest_mappings


def pytest_runtest_logreport(report):
    testplan_id = None
    params = {}
    level = "default"
    for key, value in report.user_properties:
        if key == "testplan_id":
            testplan_id = value
        elif key == "testplan_params":
            params = value
        elif key == "testplan_level":
            level = value

    if not testplan_id or _pytest_config is None:
        return

    if report.when == "call":
        outcome = report.outcome
    elif report.failed:
        outcome = "error"
    elif report.skipped and report.when == "setup":
        outcome = "skipped"
    else:
        return

    case = {
        "nodeid": report.nodeid,
        "outcome": outcome,
        "when": report.when,
        "duration": report.duration,
        "level": level,
        "params": params,
        "summary": _result_summary(report),
    }
    new = {
        "outcome": outcome,
        "duration": report.duration,
        "cases": [case],
    }
    results = _pytest_config._testplan_results
    results[testplan_id] = _merge_result(results.get(testplan_id), new)


def pytest_sessionfinish(session, exitstatus):
    if hasattr(session.config, "workerinput"):
        return

    results = session.config._testplan_results
    report_path = session.config.getoption("testplan_report_rst")
    if report_path:
        _write_testplan_report_rst(Path(report_path), results, session.config)
