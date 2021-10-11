import os
import shutil
import re
import sys
import subprocess
import argparse
import datetime
import xml.etree.ElementTree as ET

LOADABLE_RE = re.compile(
    'Loadable ([0-9]*).*tile\[([0-9]*)\] \(node "([0-9]*)", tile ([0-9]*)'
)
DISASM_RE = re.compile(".*0x([0-9a-fA-F]*): .*: \s*(\w*) \(.*")
TRACE_RE = re.compile("tile\[([0-9]*)\]@([0-9]).*--.-\.*([0-9a-fA-F]*) \((.*)\) : (.*)")
XADDR_RE = re.compile("(.*) at (.*)")
RTF_header = """{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Courier;}}
{\\colortbl;\\red0\\green0\\blue255;\\red255\\green0\\blue0;\\red51\\green102\\blue0;\\red170\\green165\\blue165;}
\\paperw23811\\paperh16838\\margl720\\margr720\\margt720\\margb720
\\fs25 Green -> compiled and executed | Red -> compiled but not executed | GRAY -> not compiled or not expected to be hit\\line
\\line
"""

disasm_loadable = None
disasm_tile = None
disasm_node = None
disasm_core = None

# Fragment from XeEngine.cpp in xobjdump source code
#      buf << "_n" << getSectorNodeNum(thisSec);
#      buf << 'c' << getSectorCoreNum(thisSec);
#      if (version != 0)
#        buf << '_' << version + 1;
def create_folder(folder):
    if not os.path.exists(folder):
        os.makedirs(folder)


# This is to read the config.xml produced by xobjdump as the naming of the elf files does not use the
# same node numbers are in the disassembly! The source code describes the node used in the file name as:
# "<node> refers to this node's jtag chain index"
def init_elf_mapping(xcov_filename):
    # global tile2node

    def get_jtag_node(node):
        for proc in node.iter("Processor"):
            return re.split("\[|\]", proc.attrib["codeReference"])[1]

    config_xml = f"{xcov_filename}/config.xml"
    tree = ET.parse(config_xml)
    root = tree.getroot()
    nodes = {}
    node_jtag_id = []
    for node in root.iter("Node"):
        if "number" in node.attrib:
            nodes[get_jtag_node(node)] = node.attrib["number"]
        if "id" in node.attrib:
            node_jtag_id.append(node.attrib["id"])

    for (node, id) in nodes.items():
        node2jtag_node[node] = node_jtag_id.index(id)


# For each node/core combination there could be two elf files. If there are two then they will be named
# e.g. image_n1c0.elf and image_n1c0_2.elf, and the first file will contain the jtag boot code.
# The naming of these files unfortunately uses the jtag chain numbering for the nodes.
# In this dict the keywords are node:core where node is the numbering taken from the disassembly file
# NOT the jtag chain index. These therefore need translating before they can be used to look up the name of
# the elf file!


def normalize_location(location):
    result = XADDR_RE.match(location)
    if result:
        fn = result.group(1)
        loca = result.group(2)
    else:
        print("Unable to parse %s" % location)
    (filename, lineno) = loca.split(":")
    if "/" in filename or filename.startswith("../"):
        filename = os.path.abspath(filename)
    fileline = "%s:%s" % (filename, lineno)
    if filename in bad_source_files:
        return fn, fileline
    if not os.path.isfile(filename):
        bad_source_files.add(filename)
        return fn, fileline
    source_files.add(filename)

    return fn, fileline


# Use xaddr2line to map the memory addresses to source line numbers
def init_addr2line(coverage_files, coverage_lines, xcov_filename):
    def update_coverage(addrs, fileline, coverage_lines, asm, fn):
        xaddress = {addrs: [0, asm, fn]}
        if fileline not in coverage_lines:
            coverage_lines[fileline] = {}
            coverage_lines[fileline]["src_hits"] = 0
            coverage_lines[fileline]["asm_hits"] = 0
            coverage_lines[fileline]["asm_addr"] = xaddress
            coverage_lines[fileline]["asm_count"] = 1
        else:
            coverage_lines[fileline]["asm_addr"].update(xaddress)
            coverage_lines[fileline]["asm_count"] += 1

    def init_coverage(addrs, fileline, asm, fn):
        if not fileline:
            return
        # If coverage_files not specified then assume all
        if coverage_files:
            for file in coverage_files:
                if file in fileline:
                    update_coverage(addrs, fileline, coverage_lines, asm, fn)
        else:
            update_coverage(addrs, fileline, coverage_lines, asm, fn)

    # Get the maximum command length from the shell
    cmd = "getconf ARG_MAX"
    arg_max = int(subprocess.check_output(cmd.split()))
    for tile in addrs_in_tile.keys():
        addrs = addrs_in_tile[tile]["addr"]
        asm = addrs_in_tile[tile]["asm"]
        assert tile not in addr2line_in_tile
        addr2line_in_tile[tile] = {}
        while len(addrs) != 0:
            (node, core) = tile2elf_id[tile].split(":")
            elf_prefix = "image_n%sc%s" % (node2jtag_node[node], core)
            # The *_2.elf is for the user code when there is a separate block of jtag boot code. Therefore
            # this doesn't always exist. If we can't find this then drop back to *.elf
            elf = "%s/%s_2.elf" % (xcov_filename, elf_prefix)
            if not os.path.isfile(elf):
                elf = "%s/%s.elf" % (xcov_filename, elf_prefix)
                if not os.path.isfile(elf):
                    print(
                        "Error: Cannot find elf file for node %s core %s" % (node, core)
                    )
                    sys.exit(1)
            cmd = "xaddr2line -p -f -e %s" % elf
            addrs_subset = []
            asm_subset = []
            while len(cmd) < (arg_max / 2) and len(addrs) != 0:
                addrs_subset.append(addrs.pop())
                asm_subset.append(asm.pop())
                cmd += " 0x%s" % addrs_subset[-1]
            results = subprocess.check_output(cmd.split())
            results = results.decode("utf-8")
            results = results.split("\n")[:-1]
            if len(addrs_subset) != len(results):
                print(
                    "Error len addrs %d results %d" % (len(addrs_subset), len(results))
                )
            locations = [normalize_location(location) for location in results]
            locations = list(zip(locations, asm_subset))
            addr2line_in_tile[tile].update(dict(zip(addrs_subset, locations)))

        for addrs, location in addr2line_in_tile[tile].items():
            init_coverage(addrs, location[0][1], location[1], location[0][0])


def parse_disasm(line):
    def add_addr(tile, addr, asm):
        if tile not in addrs_in_tile:
            addrs_in_tile[tile] = {}
            addrs_in_tile[tile]["addr"] = []
            addrs_in_tile[tile]["asm"] = []
        # addrs_in_tile[tile].add(addr)
        addrs_in_tile[tile]["addr"].append(addr)
        addrs_in_tile[tile]["asm"].append(asm)

    global disasm_loadable
    global disasm_tile
    global disasm_node
    global disasm_core

    result = DISASM_RE.match(line)
    if result:
        addr = result.group(1)
        asm = result.group(2)
        assert disasm_tile != None
        add_addr(disasm_tile, addr, asm)
    else:
        result = LOADABLE_RE.match(line)
        if result:
            (disasm_loadable, disasm_tile, disasm_node, disasm_core) = result.groups()
            elf_id = ":".join([disasm_node, disasm_core])
            if disasm_tile in tile2elf_id:
                assert tile2elf_id[disasm_tile] == elf_id
            else:
                tile2elf_id[disasm_tile] = elf_id


def parse_trace(tracefile, coverage_lines):
    def addr2line(tile, addr):
        if addr in addr2line_in_tile[tile]:
            return addr2line_in_tile[tile][addr][0][1]
        if not addr.startswith("fff"):
            print("addr2line failure:tile %s addr %s" % (tile, addr))
        return "UNKNOWN:?"

    def has_src_line_changed(tile, thread, fileline, covstate):
        if (tile, thread) not in covstate:
            covstate[(tile, thread)] = {"srcline": fileline, "linecount": 1}
            return True

        has_changed = (covstate[(tile, thread)]["srcline"] != fileline) or (
            covstate[(tile, thread)]["linecount"]
            == coverage_lines[fileline]["asm_count"]
        )
        if has_changed:
            covstate[(tile, thread)]["srcline"] = fileline
            covstate[(tile, thread)]["linecount"] = 1
        else:
            covstate[(tile, thread)]["linecount"] += 1
        return has_changed

    def add_to_trace(tile, thread, addr, fn, asm, covstate):
        id = ":".join([tile, addr])
        if id not in trace_cache:
            trace_cache[id] = [fn, asm, addr2line(tile, addr)]
        fileline = trace_cache[id][2]
        if fileline in coverage_lines:
            if fileline:
                coverage_lines[fileline]["asm_hits"] += 1
                if addr in coverage_lines[fileline]["asm_addr"].keys():
                    coverage_lines[fileline]["asm_addr"][addr][0] += 1

    def find_par(codeline, addrs_list):
        merge_list = [[]]
        grp = 0
        par = False
        merge_list[grp] = addrs_list[0]
        for i, addrss in enumerate(addrs_list):
            if addrs_list[grp][-1][1][1] != "dualentsp":
                if i != (len(addrs_list) - 1):
                    merge_list[grp] += addrs_list[i + 1]
            else:
                if i != (len(addrs_list) - 1):
                    par = True
                    merge_list.append(addrs_list[i + 1])
                    grp += 1
                if par:
                    par_fn.append([addrs_list[i][-1][1][2], codeline])

        return merge_list

    def anal_src_addrs(codeline, addr_list, par_fd=True):
        grp = 0
        addrs_list = [[]]
        for addrs, ct_asm in addr_list:
            ad_ct = [addrs, ct_asm]
            if not (addrs_list[0]):
                addrs_list[grp].append(ad_ct)
            else:
                if ((int(addrs_list[grp][-1][0], 16) + 2) == int(addrs, 16)) or (
                    (int(addrs_list[grp][-1][0], 16) + 4) == int(addrs, 16)
                ):
                    addrs_list[grp].append(ad_ct)
                else:
                    addrs_list.append([ad_ct])
                    grp += 1
        if par_fd:
            addrs_list = find_par(codeline, addrs_list)
        else:
            coverage_lines[codeline]["src_hits"] = 0
        for i, addrss in enumerate(addrs_list):
            asm_hits = []
            for addrs, ctandasm in addrss:
                asm_hits.append(coverage_lines[codeline]["asm_addr"][addrs][0])
            max_hits = max(asm_hits)
            coverage_lines[codeline]["src_hits"] += max_hits

    # Keep a track of the current source line for each tile so we only increment coverage counts
    # when we move to a new source line. It also needs to keep a record of the number of cycles the
    # current line has been executed to cope with the case where the same line is executed
    # repeatedly.
    covstate = {}
    par_fn = []
    with open(tracefile) as tracefd:
        line = tracefd.readline()
        lineno = 1
        while line:
            result = TRACE_RE.match(line)
            if result:
                (tile, thread, addr, fn, asm) = result.groups()
                add_to_trace(tile, thread, addr, fn, asm, covstate)
            else:
                print("Unable to parse line: %s" % line)

            line = tracefd.readline()
            lineno += 1
        for keys, value in coverage_lines.items():
            asm_addrs_items = coverage_lines[keys]["asm_addr"].items()
            sorted_items = sorted(asm_addrs_items)
            # print(keys, sorted_items)
            anal_src_addrs(keys, sorted_items)
        par_fn_thread = []
        par_location = set()
        par_fn_thread += (thread_name for thread_name, codeline in par_fn)
        for keys, value in coverage_lines.items():
            for i, vi in enumerate(par_fn):
                if keys not in vi[1]:
                    asm_addrs_items = coverage_lines[keys]["asm_addr"].items()
                    sorted_items = sorted(asm_addrs_items)
                    for i, v in enumerate(sorted_items):
                        for thread_name in par_fn_thread:
                            if v[1][2] in thread_name:
                                if keys not in par_location:
                                    par_location.add(keys)
                                    anal_src_addrs(keys, sorted_items, False)
                                break
                    break


# Assumes that source lines are of the form "path_to_file:line_number"
def line_key(line):
    try:
        return int(line.split(":")[1])
    except:
        return 0


def escape_bracket(line):
    bracket_loc = []
    count = 0
    content = ""
    for i in line:
        if i == "{" or i == "}":
            bracket_loc.append(count)
        count += 1
    if len(bracket_loc):
        offset = 0
        for value in bracket_loc:
            content = line[0 : value + offset] + "\\" + line[value + offset :]
            offset += 1
    else:
        content = line
    return content


def write_rtf(rtf, lines, src_hits):
    GREEN = "\\cf3"
    GRAY = "\\cf4"
    RED = "\\cf2"
    rline = escape_bracket(lines)
    if src_hits == -1:  # not compiled
        rtf.write("%s %s \\line" % (GRAY, rline))
    elif src_hits == "hit":  # compiled and executed
        rtf.write("%s %s \\line" % (GREEN, rline))
    else:  # compiled but not executed
        rtf.write("%s %s \\line" % (RED, rline))


"""
xcov_process description:
This is the main function to be called in your test.
It returns the average coverage and save the data in .xcov file in xcov dir.
.xcov file is necessary for the below "xcov_combine" function.

@param disam: path to disasm file
@param trace: path to trace file
@param xcov_dir : path where xcov directory locates
@return average coverage of all src file
@output generate xcov file for xcov_combine and save in xcov dir
"""


def xcov_process(disasm, trace, xcov_filename):

    global node2jtag_node
    global addrs_in_tile
    global addr2line_in_tile
    global trace_cache
    global tile2elf_id
    node2jtag_node = {}
    addrs_in_tile = {}
    addr2line_in_tile = {}
    trace_cache = {}
    tile2elf_id = {}
    # Set of source files which exist
    global source_files
    source_files = set()
    # Set of source files which do not exist
    global bad_source_files
    bad_source_files = set()

    coverage_lines = {}

    coverage_files = None
    if not coverage_files:
        print("Generating coverage for all source files")

    covdir = os.path.join(xcov_filename, "xcov")
    create_folder(covdir)

    init_elf_mapping(xcov_filename)

    print("Reading disassembly")
    with open(disasm) as disasmfd:
        line = disasmfd.readline()
        lineno = 1
        while line:
            parse_disasm(line)
            line = disasmfd.readline()
            lineno += 1

    # Populate addr2line lookup from the disassembly
    init_addr2line(coverage_files, coverage_lines, xcov_filename)

    print("Reading trace")
    parse_trace(trace, coverage_lines)
    print("End of reading trace")

    coverage = {}
    if coverage_files:
        # These may not be fully qualified pathnames so grab the ones from the list
        # of source files, which will be full path names.
        pathnames = []
        for file in coverage_files:
            for src in source_files:
                if file in src:
                    pathnames.append(src)
        coverage_files = pathnames
    else:
        coverage_files = source_files

    for file in coverage_files:
        file = str(file)
        coverage[file] = []
        for codeline in coverage_lines:
            if file in codeline:
                coverage[file].append(codeline)
    total_src_covered = 0
    total_src = 0
    for file in coverage_files:
        file = str(file)
        covfile = "%s/%s.xcov" % (covdir, file.replace("/", "__"))
        covoutfd = open(covfile, "w")
        nocov = 0
        for codeline in sorted(coverage[file], key=line_key):
            if coverage_lines[codeline]["src_hits"] == 0:
                nocov += 1
            covoutfd.write(
                "%s:%s:%s:%s\n"
                % (
                    codeline.split(":")[1],
                    coverage_lines[codeline]["src_hits"],
                    coverage_lines[codeline]["asm_hits"],
                    coverage_lines[codeline]["asm_count"],
                )
            )
        coverage_rate = float(100 * (len(coverage[file]) - nocov) / len(coverage[file]))
        total_src_covered += len(coverage[file]) - nocov
        total_src += len(coverage[file])
        print("%s: %f%% covered" % (file, coverage_rate))
    total_coverage = float(100 * (total_src_covered / total_src))
    print("Total coverage: %f%% covered" % total_coverage)
    return total_coverage


"""
xcov_combine description:
This function read data (.xcov file) from xcov dir and create .rtf files which show the details of executed source code.

@param xcov_dir: path where xcov directory locates
@output .coverage and .rtf files
"""


class xcov_combine():

    def __init__(self):
        self.coverage = {}

    def get_result_files(self, xcov_dir):
        files = []
        # for dir in dirs:
        xdir = os.path.join(xcov_dir, "xcov")
        for file in os.listdir(xdir):
            if file.endswith(".xcov"):
                files.append(os.path.join(xdir, file))
        return files

    def file2covfile(self, file):
        return os.path.basename(file).replace("__", "/").replace(".xcov", "")

    def init_coverage(self, files):
        covfiles = set()
        for file in files:
            covfiles.add(self.file2covfile(file))
        for covfile in covfiles:
            if covfile not in self.coverage:
                self.coverage[covfile] = {}
        return self.coverage

    def combine_results(self, files, coverage, xcov_dir):
        for file in files:
            filename = self.file2covfile(file)
            print("Processing %s" % file)
            with open(file, "r") as fd:
                for line in fd:
                    (lineno, src_hits, asm_hits, asm_count) = line.split(":")
                    try:
                        lineno = int(lineno)
                    except:
                        if lineno == "?":
                            print("Error unknown location at %s" % filename)
                        else:
                            print("Error converting line number to int in %s" % line)
                        continue
                    src_hits = int(src_hits)
                    asm_hits = int(asm_hits)
                    asm_count = int(asm_count)
                    if lineno not in coverage[filename]:
                        coverage[filename][lineno] = {}
                        coverage[filename][lineno]["src_hits"] = 0
                        coverage[filename][lineno]["asm_hits"] = 0
                        coverage[filename][lineno]["asm_count_max"] = asm_count
                        coverage[filename][lineno]["asm_count_min"] = asm_count
                    # The asm count for a given source line may be different between executables
                    if asm_count < coverage[filename][lineno]["asm_count_min"]:
                        coverage[filename][lineno]["asm_count_min"] = asm_count
                    if asm_count > coverage[filename][lineno]["asm_count_max"]:
                        coverage[filename][lineno]["asm_count_max"] = asm_count
                    coverage[filename][lineno]["src_hits"] += src_hits
                    coverage[filename][lineno]["asm_hits"] += asm_hits
            #delete .xcov after combined
            os.remove(file)

        #for multi-processing
        pid = os.getpid()
        wt = open("tmp_testresult_%d.txt"%pid, "w+")

        if os.stat("tmp_testresult_%d.txt"%pid).st_size == 0:
            for filename in coverage:
                for lineno in coverage[filename]:
                    wt.write("%s:%d:%d\n" % (filename, lineno, coverage[filename][lineno]["src_hits"]))
                    # wt.write("asm hit: %s %d %d\n" % (filename, lineno, coverage[filename][lineno]["asm_hits"]))
        else:
            lines = wt.readlines()
            fn_and_line = {}
            for line in lines:
                fname, linenumber, hits = line.split(":")
                fnandline = fname+":"+linenumber
                fn_and_line[fnandline] = int(hits)
            for filename in coverage:
                for lineno in coverage[filename]:
                    if ("%s:%d"%(filename, lineno)) in fn_and_line:
                        new_hits = coverage[filename][lineno]["src_hits"] + fn_and_line["%s:%d"%(filename, lineno)]
                        fn_and_line["%s:%d"%(filename, lineno)] = new_hits
                        # wt.write("%s:%d:%d\n" % (filename, lineno, new_hits))
                    else:
                        fn_and_line["%s:%d"%(filename, lineno)] = coverage[filename][lineno]["src_hits"]
                        # wt.write("%s:%d:%d\n" % (filename, lineno, coverage[filename][lineno]["src_hits"]))
            for key, value in fn_and_line.items():
                fname, linenumber = line.split(":")
                wt.write("%s:%d:%d\n" % (fname, linenumber, value))

    def remove_tmp_testresult(self, path):
        for file in os.listdir(path):
            if file.startswith("tmp_testresult_"):
                os.remove(file)

    def generate_coverage(self, logs_path, coverage):
        for (file, counts) in coverage.items():
            annotated = "%s/%s.coverage" % (logs_path, file.replace("/", "__"))
            rtf_name = "%s/%s.rtf" % (logs_path, file.replace("/", "__"))
            rtf_f = open(rtf_name, "w")
            rtf_f.write(RTF_header)
            with open(annotated, "w") as outfd:
                with open(file, "r") as srcfd:
                    lineno = 1
                    for line in srcfd:
                        if lineno in counts:
                            prefix = "%s" % (
                                "{:8s} ".format(counts[lineno]),
                                # "{:5d} ".format(counts[lineno]["asm_hits"]),
                                # "{:3d} ".format(counts[lineno]["asm_count_max"]),
                                # "{:3d} ".format(counts[lineno]["asm_count_min"]),
                            )
                            rtf_prefix = "%s" % (
                                "{:8s} ".format(counts[lineno])
                            )
                            write_rtf(
                                rtf_f,
                                "%s: %s" % (rtf_prefix, line),
                                counts[lineno],
                            )
                        else:
                            prefix = 9 * " "
                            rtf_prefix = 9 * " "
                            write_rtf(rtf_f, "%s: %s" % (rtf_prefix, line), -1)
                        outfd.write("%s: %s" % (prefix, line))
                        lineno += 1
            rtf_f.write("}")
            rtf_f.close()
            print("Written coverage to %s" % annotated)

    def run_combine(self, xcov_dir):
        files = self.get_result_files(xcov_dir)
        coverage = self.init_coverage(files)
        self.combine_results(files, coverage, xcov_dir)

"""
combine_tests description:
This function merge the result over different tests and return the average coverage of all tests.

@param testpath: path where test_ files locate
@param specified_test: specify test result to be combined. Type: set([]). Default: walk through all test_ file which have xcov dir
@return average coverage of all test
@output generate a overall test report that indicate the overall coverage and the uncovered source code
"""

class combine_tests(xcov_combine):

    def __init__(self, testpath):
        self.result = {}
        self.tpath = testpath
        create_folder("result")
        self.resufd = open("%s/result/xcoverage_result.txt" % testpath, "w")
        super().__init__()

    def close_fd(self):
        self.resufd.close()

    # def find_xcov(self, testpath, specified_test):
    #     xcov_file_merge = {}

    #     def find_file_and_del_log(test_file):
    #         test_module = os.path.join(testpath, test_file)
    #         if os.path.isdir(test_module) and test_file.startswith("test_"):
    #             for test_dir in os.walk(test_module):
    #                 if test_dir[0].endswith("/xcov"):
    #                     xcov_list = []
    #                     for xcov_file in test_dir[2]:
    #                         if xcov_file.endswith(".xcov"):
    #                             xcov_list.append(xcov_file)
    #                     xcov_file_merge[str(test_dir[0])] = xcov_list
    #                 if test_dir[0].endswith("/logs"):
    #                     shutil.rmtree(test_dir[0])

    #     if not specified_test:
    #         if os.path.isdir(testpath):
    #             for test_file in os.listdir(testpath):
    #                 find_file_and_del_log(test_file)
    #         else:
    #             raise Exception("%s not found" % testpath)
    #     else:
    #         for spec_test in specified_test:
    #             if spec_test in os.listdir(testpath):
    #                 find_file_and_del_log(spec_test)
    #             else:
    #                 raise Exception("%s not found" % spec_test)
    #     return xcov_file_merge

    def find_testresult(self, path):
        testresult = []
        for file in os.listdir(path):
            if file.startswith("tmp_testresult_"):
                testresult.append(file)
        return testresult

    def do_merge_result(self, merge_file):
        for test in merge_file:
            with open(test, "r") as resfd:
                for line in resfd:
                    srcloc, lineno, hitcount = line.split(":")
                    lineno = int(lineno)
                    hitcount = hitcount[0:-1]
                    if srcloc not in self.result:
                        self.result[srcloc] = {}
                    if lineno not in self.result[srcloc]:
                        if hitcount != "0":
                            self.result[srcloc][lineno] = "hit"
                        else:
                            self.result[srcloc][lineno] = "not hit"
                    else:
                        if hitcount != "0":
                            self.result[srcloc][lineno] = "hit"
        return self.result

    def cal_xcoverage(self, merged_result):
        no_src = 0
        no_hit = 0
        not_hit = {}
        for key, value in merged_result.items():
            for line, hitc in value.items():
                no_src += 1
                if hitc == "hit":
                    no_hit += 1
                elif hitc == "not hit":
                    if key not in not_hit:
                        not_hit[key] = []
                    not_hit[key].append(line)

        return (no_hit / no_src) * 100, not_hit

    def do_combine_test(self, specified_test=set([])):
        need_merge = self.find_testresult(self.tpath)
        merged_result = self.do_merge_result(need_merge)
        xcoverage_result, not_hit = self.cal_xcoverage(merged_result)
        # with open("%s/xcoverage_result.txt" % testpath, "w+") as resufd:
        self.resufd.write("Included test:%s\n" % specified_test)
        self.resufd.write(
            "Total coverage = %f%%\nSource code uncovered: \n" % xcoverage_result
        )
        for key, value in not_hit.items():
            self.resufd.write("%s at line:\n" % key.replace("__", "/").replace(".xcov", ""))
            self.resufd.write("%s\n" % value)
        return xcoverage_result 

    #running at the end of test
    def generate_merge_src(self, logpath):
        logp = os.path.join(self.tpath, logpath)
        self.generate_coverage(logp, self.result)