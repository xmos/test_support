# Copyright 2016-2021 XMOS LIMITED.
# This Software is subject to the terms of the XMOS Public Licence: Version 1.
import re
import sys
from typing import Optional, Sequence, Union


class TestError(Exception):
    """
    This exception is used for any errors that occur whilst calling
    functions in the Pyxsim module.
    """

    def __init__(self, value):
        super().__init__(self)
        self.value = value

    def __str__(self):
        return repr(self.value)


class PytestComparisonTester:
    """
    This tester is designed for use with Pytest assert statements; it will 
    compare output against a file and pass the test if the output matches.
    There are 5 failure modes: the output is longer than expected, shorter than
    expected, does not contain an expected line, contains an unexpected line, or
    contains all expected lines but in an incorrect order (if ordered is True).

     :param golden:     The expected data to compare the output against.
                        Should be a path to a file to read, or a list of strings
     :param regexp:     A bool that controls whether the expect lines are 
                        treated as regular expressions or not.
     :param ordered:    A bool that determins whether the expected input needs
                        to be matched in an ordered manner or not.
     :param ignore:     A list of regular expressions to ignore. If 
                        suppress_multidrive_messages is set to True, this will
                        be in addition to these.
     :param suppress_multidrive_messages:
                        A bool that determines whether lines beginning with
                        'Internal control pad and plugin driving in opposite 
                        directions' should be ignored. Defaults to True.
    """

    def __init__(self,
                 golden: Union[str, Sequence[str]],
                 regexp: bool,
                 ordered: bool,
                 ignore: Optional[Sequence[str]] = None,
                 suppress_multidrive_messages: bool = True
        ) -> None:
        self._golden = golden
        self._regexp = regexp
        self._ordered = ordered
        self._ignore = ignore
        self._smm = suppress_multidrive_messages

    def run(self, output: Union[str, Sequence[str]]):
        regexp = self._regexp
        ordered = self._ordered
        ignore = self._ignore
        golden = self._golden

        if type(golden) == str:
            with open(self._golden) as golden:
                expected = [x.strip() for x in golden.readlines()]
        else: 
            expected = [x.strip() for x in golden]
        
        if expected:
            if expected[0].strip() == "":
                expected = expected[1:]
        if expected:
            if expected[-1].strip() == "":
                expected = expected[:-1]

        # Strip captured data of leading/trailing whitespace and apply filtering
        if type(output) == str:
            capture = [x.strip() for x in output.split("\n")]
        else:
            capture = [x.strip() for x in output]

        if self._smm:
            capture = [x for x in capture if not x.startswith("Internal control pad and plugin driving in opposite directions")]
        if ignore:
            for pattern in ignore:
                capture = [x for x in capture if not re.search(pattern, x)]
        if capture:
            if capture[0].strip() == "":
                capture = capture[1:]
        if capture:
            if capture[-1].strip() == "":
                capture = capture[:-1]

        # The essential principle here is that we don't want to loop over the 
        # data until we really can't avoid it any longer.
        
        # Test that the capture is not too short
        assert len(capture) >= len(expected), f"Length of output less than expected \n{capture} \n{expected}"
        
        # Test that the capture is not too long
        assert len(capture) <= len(expected), f"Length of output greater than expected \n{capture} \n{expected}"


        if not regexp and not ordered:
            # If the output and expected do not need to match as regexps, and we
            # don't care about order, then simple set comparison
            # can determine unexpected lines/absences in the output

            # Test that the capture contains all expected lines
            assert set(capture) >= set(expected), f"Output does not contain all expected lines \n{capture} \n{expected}"

            # Test that the capture does not contain an unexpected line
            assert set(capture) <= set(expected), f"Output contains unexpected lines \n{capture} \n{expected}"
        
        else:
            # Otherwise, we need to loop over the whole dataset. 
            # Let's handle ordered and unordered cases separately.
            if ordered:
                # We know that the two lists are the same length, so we can zip
                # them together to analyse line by line.
                for l_num, (c_val, e_val) in enumerate(zip(capture, expected)):
                    if regexp:
                        assert re.match("^" + e_val + "$", c_val), f"Output ({c_val}) does not match expected regex ({e_val}) at line {l_num}"
                    else:
                        assert e_val == c_val, f"Output ({c_val}) does not match expected ({e_val}) at line {l_num}"
            else:
                # We're unordered and we know that regexp must be True.
                # We therefore require that for every line in capture there
                # exists at least one line in expected that matches.
                for c_val in capture:
                    assert any(re.match(e_val, c_val) for e_val in expected), f"Cannot find regex match for output ({c_val})"
                # And that for every line in expected there exists at least one 
                # line in capture that matches (these are two different things!)
                for e_val in expected:
                    assert any(re.match(e_val, c_val) for c_val in capture), f"Cannot find regex match for expectation ({e_val})"
                    

class ComparisonTester:
    """
    This tester will compare ouput against a file and pass a test if
    the output matches

     :param golden:   The expected data to compare the output against.
                      Can be a list of strings, a string split on new lines,
                      or a file to read.
     :param product:  The name of the product that is being
                      tested e.g. 'lib_uart'
     :param group:    The group that the test belongs to
     :param test:     The name of the test
     :param config:   A dictionary representing the configuration of the test.
     :param env:      A dictionary representing the environment the test was
                      run under.
     :param regexp:   A bool that controls whether the expect lines are treated
                      as regular expressions or not.
     :param ignore:   A list of regular expressions to ignore
     :param ordered:  A bool that determines whether the expected input needs
                      to be matched in an ordered manner or not.
    """

    def __init__(
        self,
        golden,
        product,
        group,
        test,
        config={},
        env={},
        regexp=False,
        ignore=[],
        ordered=True,
    ):
        # self.register_test(product, group, test, config)
        self._golden = golden
        self._test = (product, group, test, config, env)
        self._regexp = regexp
        self._ignore = ignore
        self._ordered = ordered
        self.result = None
        self.failures = []

    def record_failure(self, failure_reason):
        # Append a newline if there isn't one already
        if not failure_reason.endswith("\n"):
            failure_reason += "\n"
        self.failures.append(failure_reason)
        sys.stderr.write("ERROR: %s" % failure_reason)
        self.result = False

    def run(self, output):
        golden = self._golden
        (_product, _group, test, config, _env) = self._test
        regexp = self._regexp
        if isinstance(golden, list):
            expected = golden
        elif isinstance(golden, str):
            expected = golden.split("\n")
        else:
            expected = [x.strip() for x in golden.readlines()]
        if expected[0].strip() == "":
            expected = expected[1:]
        if expected[-1].strip() == "":
            expected = expected[:-1]
        self.result = True
        self.failures = []
        line_num = -1

        num_expected = len(expected)

        for line in output:
            ignore = False
            for p in self._ignore:
                if re.match(p, line.strip()):
                    ignore = True
                    break
            if ignore:
                continue
            line_num += 1

            if line_num >= num_expected:
                self.record_failure("Length of expected output less than output")
                break

            if self._ordered:
                if regexp:
                    match = re.match(expected[line_num] + "$", line.strip())
                else:
                    match = expected[line_num] == line.strip()

                if not match:
                    self.record_failure(
                        (
                            "Line %d of output does not match expected\n"
                            + "  Expected: %s\n"
                            + "  Actual  : %s"
                        )
                        % (
                            line_num,
                            expected[line_num].strip(),
                            line.strip(),
                        )
                    )
            else:  # Unordered testing
                stripped = line.strip()
                if regexp:
                    match = any(re.match(e + "$", stripped) for e in expected)
                else:
                    match = any(e == stripped for e in expected)

                if not match:
                    self.record_failure(
                        ("Line %d of output not found in expected\n" + "  Actual  : %s")
                        % (line_num, line.strip())
                    )

        if num_expected > line_num + 1:
            self.record_failure(
                "Length of expected output greater than output\nMissing:\n"
                + "\n".join(expected[line_num + 1 :])  # noqa E203
            )
        output = {"output": "".join(output)}

        if not self.result:
            output["failures"] = "".join(self.failures)

        if self.result:
            sys.stdout.write(
                "%-30s %-6s %-6s Pass\n"
                % (test, config.get("arch"), config.get("speed"))
            )
        else:
            sys.stderr.write(
                "%-30s %-6s %-6s Fail\n"
                % (test, config.get("arch"), config.get("speed"))
            )

        return self.result
