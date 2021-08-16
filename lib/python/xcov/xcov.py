import os
import shutil
import re
import sys
import subprocess
import argparse
import datetime
import xml.etree.ElementTree as ET

LOADABLE_RE = re.compile("Loadable ([0-9]*).*tile\[([0-9]*)\] \(node \"([0-9]*)\", tile ([0-9]*)")
DISASM_RE = re.compile(".*0x([0-9a-fA-F]*):.*")
TRACE_RE = re.compile("tile\[([0-9]*)\]@([0-9]).*----\.*([0-9a-fA-F]*) \((.*)\) : (.*)")

node2jtag_node = {}

# Fragment from XeEngine.cpp in xobjdump source code
#      buf << "_n" << getSectorNodeNum(thisSec);
#      buf << 'c' << getSectorCoreNum(thisSec);
#      if (version != 0)
#        buf << '_' << version + 1;

# This is to read the config.xml produced by xobjdump as the naming of the elf files does not use the
# same node numbers are in the disassembly! The source code describes the node used in the file name as:
# "<node> refers to this node's jtag chain index"
def init_elf_mapping():
    global tile2node

    def get_jtag_node(node):
        for proc in node.iter('Processor'):
            return re.split("\[|\]", proc.attrib['codeReference'])[1]

    tree = ET.parse('config.xml')
    root = tree.getroot()
    nodes = {}
    node_jtag_id = []
    for node in root.iter('Node'):
        if 'number' in node.attrib:
            nodes[get_jtag_node(node)] = node.attrib['number']
        if 'id' in node.attrib:
            node_jtag_id.append(node.attrib['id'])

    for (node, id) in nodes.items():
        node2jtag_node[node] = node_jtag_id.index(id)

addrs_in_tile = {}
addr2line_in_tile = {}

trace_cache = {}

# For each node/core combination there could be two elf files. If there are two then they will be named
# e.g. image_n1c0.elf and image_n1c0_2.elf, and the first file will contain the jtag boot code.
# The naming of these files unfortunately uses the jtag chain numbering for the nodes.
# In this dict the keywords are node:core where node is the numbering taken from the disassembly file
# NOT the jtag chain index. These therefore need translating before they can be used to look up the name of
# the elf file!

# Set of source files which exist
source_files = set()
# Set of source files which do not exist
bad_source_files = set()

def normalize_location(location):
    (filename, lineno) = location.split(":")
    if "/" in filename or filename.startswith("../"):
        filename = os.path.abspath(filename)
    fileline = "%s:%s" % (filename, lineno)
    # print(filename, lineno)
    if filename in bad_source_files:
        return fileline
    if not os.path.isfile(filename):
        bad_source_files.add(filename)
        # if args.verbose:
        #     print("Unable to find source file %s" % filename)
        return fileline
    source_files.add(filename)

    return fileline

# Use xaddr2line to map the memory addresses to source line numbers
def init_addr2line(coverage_files, coverage_lines):
    def update_coverage(fileline, coverage_lines):
        if fileline not in coverage_lines:
            coverage_lines[fileline] = {}
            coverage_lines[fileline]['src_hits'] = 0
            coverage_lines[fileline]['asm_hits'] = 0
            coverage_lines[fileline]['asm_count'] = 1
        else:
            coverage_lines[fileline]['asm_count'] += 1

    def init_coverage(fileline):
        if not fileline:
            return
        # If coverage_files not specified then assume all
        if coverage_files:
            for file in coverage_files:
                if file in fileline:
                    update_coverage(fileline, coverage_lines)
        else:
            update_coverage(fileline, coverage_lines)

    # Get the maximum command length from the shell
    cmd = "getconf ARG_MAX"
    arg_max = int(subprocess.check_output(cmd.split()))
    for tile in addrs_in_tile.keys():
        addrs = addrs_in_tile[tile]
        assert(tile not in addr2line_in_tile)
        addr2line_in_tile[tile] = {}
        while len(addrs) != 0:
            (node, core) = tile2elf_id[tile].split(":")
            elf_prefix = "image_n%sc%s" % (node2jtag_node[node], core)
            # The *_2.elf is for the user code when there is a separate block of jtag boot code. Therefore
            # this doesn't always exist. If we can't find this then drop back to *.elf
            elf = "%s_2.elf" % elf_prefix
            if not os.path.isfile(elf):
                elf = "%s.elf" % elf_prefix
                if not os.path.isfile(elf):
                    print("Error: Cannot find elf file for node %s core %s" % (node, core))
                    sys.exit(1)
            cmd = "xaddr2line -e %s" % elf
            addrs_subset = []
            while len(cmd) < (arg_max / 2) and len(addrs) != 0:
                addrs_subset.append(addrs.pop())
                cmd += ' 0x%s' % addrs_subset[-1]
            results = subprocess.check_output(cmd.split())
            results = results.decode('utf-8')   
            results = results.split("\n")[:-1]
            # print(results)
            if len(addrs_subset) != len(results):
                print("Error len addrs %d results %d" % (len(addrs_subset), len(results)))
            locations = [normalize_location(location) for location in results]
            addr2line_in_tile[tile].update(dict(zip(addrs_subset, locations)))
            for keys, values in addr2line_in_tile[tile].items():
                print(keys, values)
        for location in addr2line_in_tile[tile].values():
            init_coverage(location)

disasm_loadable = None
disasm_tile = None
disasm_node = None
disasm_core = None

tile2elf_id = {}

def parse_disasm(line):
    def add_addr(tile, addr):
        if tile not in addrs_in_tile:
            addrs_in_tile[tile] = set()
        addrs_in_tile[tile].add(addr)

    global disasm_loadable
    global disasm_tile
    global disasm_node
    global disasm_core
    result = DISASM_RE.match(line)
    if result:
        addr = result.group(1)
        assert(disasm_tile != None)
        add_addr(disasm_tile, addr)
    else:
        result = LOADABLE_RE.match(line)
        if result:
            (disasm_loadable, disasm_tile, disasm_node, disasm_core) = result.groups()
            # if args.verbose:
            #     print("Loadable %s tile %s node %s core %s" %
            #           (disasm_loadable, disasm_tile, disasm_node, disasm_core))
            elf_id = ":".join([disasm_node, disasm_core])
            if disasm_tile in tile2elf_id:
                assert(tile2elf_id[disasm_tile] == elf_id)
            else:
                tile2elf_id[disasm_tile] = elf_id

def parse_trace(tracefile, coverage_lines):
    def addr2line(tile, addr):
        if addr in addr2line_in_tile[tile]:
            return addr2line_in_tile[tile][addr]
        if not addr.startswith('fff'):
            print("addr2line failure:tile %s addr %s" % (tile, addr))
        return "UNKNOWN:?"

    def has_src_line_changed(tile, thread, fileline, covstate):
        if (tile, thread) not in covstate:
            covstate[(tile, thread)] = {'srcline': fileline, 'linecount': 1}
            return True

        has_changed = ((covstate[(tile, thread)]['srcline'] != fileline) or
                       (covstate[(tile, thread)]['linecount'] == coverage_lines[fileline]['asm_count']))
        if has_changed:
            covstate[(tile, thread)]['srcline'] = fileline
            covstate[(tile, thread)]['linecount'] = 1
        else:
            covstate[(tile, thread)]['linecount'] += 1
        return has_changed

    def add_to_trace(tile, thread, addr, fn, asm, covstate):
        id = ':'.join([tile, addr])
        if id not in trace_cache:
            trace_cache[id] = [fn, asm, addr2line(tile, addr)]
        fileline = trace_cache[id][2]
        if fileline in coverage_lines:
            if fileline:
                coverage_lines[fileline]['asm_hits'] += 1
                if has_src_line_changed(tile, thread, fileline, covstate):
                    coverage_lines[fileline]['src_hits'] += 1

    # Keep a track of the current source line for each tile so we only increment coverage counts
    # when we move to a new source line. It also needs to keep a record of the number of cycles the
    # current line has been executed to cope with the case where the same line is executed
    # repeatedly.
    covstate = {}
    with open(tracefile) as tracefd:
        line = tracefd.readline()
        lineno = 1
        while line:
            result = TRACE_RE.match(line)
            if result:
                (tile, thread, addr, fn, asm) = result.groups()
                add_to_trace(tile, thread, addr, fn, asm, covstate)
            # else:
                # print("Unable to parse line: %s" % line)

            line = tracefd.readline()
            lineno += 1

# Assumes that source lines are of the form "path_to_file:line_number"
def line_key(line):
    try:
        return int(line.split(":")[1])
    except:
        return 0

def handler_process():
    coverage_lines = {}

    coverage_files = None
    if not coverage_files:
        print("Generating coverage for all source files")

    covdir = "%s_%s" % ("xcovv",
                        datetime.datetime.now().strftime('%Y-%m-%d-%H%M%S'))

    # build_system(covdir, args.binary, args.xmake, args.clean, args.tracefile)

    init_elf_mapping()

    print("Reading disassembly")
    with open("disasm.dump") as disasmfd:
        line = disasmfd.readline()
        lineno = 1
        while line:
            parse_disasm(line)
            line = disasmfd.readline()
            lineno += 1

    # Populate addr2line lookup from the disassembly
    init_addr2line(coverage_files, coverage_lines)

    for keys, values in coverage_lines.items():
        print(keys, values)
        # print(i.keys())
    print("Reading trace")
    parse_trace("trace.dump", coverage_lines)
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
        # print(file)
        coverage[file] = []
        for codeline in coverage_lines:
            if file in codeline:
                coverage[file].append(codeline)
    # print("bad_source_file: %s" % bad_source_files)
    for file in coverage_files:
        file = str(file)
        covfile = "%s.xcov" % file.replace("/", "__")
        covoutfd = open(covfile, "w")
        nocov = 0
        # print("Line coverage for %s saved in %s/%s" % (file, covdir, covfile))
        for codeline in sorted(coverage[file], key=line_key):
            if coverage_lines[codeline]['src_hits'] == 0:
                nocov += 1
            covoutfd.write("%s:%s:%s:%s\n" % (codeline.split(":")[1],
                                              coverage_lines[codeline]['src_hits'],
                                              coverage_lines[codeline]['asm_hits'],
                                              coverage_lines[codeline]['asm_count']))
        # print("End of coverage for %s\n --> %d lines of %d with no coverage" % (file, nocov, len(coverage[file])))
        coverage_rate = float(100 * (len(coverage[file])-nocov)/len(coverage[file]))
        # print("%f%% coverage of %s" % (coverage_rate, file))
        print("%s: %f%% covered" % (file, coverage_rate))

def handler_combine():
    def get_test_dirs():
        if 0:
            dirs = args.dirs
        else:
            dirs = []
            for dir in os.listdir('.'):
                if dir.startswith('xcov_'):
                    dirs.append(dir)
        return dirs

    def get_result_files(dirs):
        files = []
        # for dir in dirs:
        dir = "xcov_"
        for file in os.listdir("."):
            if file.endswith('.xcov'):
                # files.append('/'.join([dir, file]))
                files.append(file)
        return files

    def file2covfile(file):
        return os.path.basename(file).replace("__", "/").replace(".xcov", "")

    def init_coverage(files):
        covfiles = set()
        for file in files:
            covfiles.add(file2covfile(file))
        coverage = {}
        for covfile in covfiles:
            coverage[covfile] = {}
        return coverage

    def combine_results(files, coverage):
        for file in files:
            filename = file2covfile(file)
            print("Processing %s" % file)
            with open(file, 'r') as fd:
                for line in fd:
                    (lineno, src_hits, asm_hits, asm_count) = line.split(":")
                    try:
                        lineno = int(lineno)
                    except:
                        if lineno == "?":
                            print("Error unknow location at %s" % filename)
                        else:
                            print("Error converting line number to int in %s" % line)
                        continue
                    src_hits = int(src_hits)
                    asm_hits = int(asm_hits)
                    asm_count = int(asm_count)
                    if lineno not in coverage[filename]:
                        coverage[filename][lineno] = {}
                        coverage[filename][lineno]['src_hits'] = 0
                        coverage[filename][lineno]['asm_hits'] = 0
                        coverage[filename][lineno]['asm_count_max'] = asm_count
                        coverage[filename][lineno]['asm_count_min'] = asm_count
                    # The asm count for a given source line may be different between executables
                    if asm_count < coverage[filename][lineno]['asm_count_min']:
                        coverage[filename][lineno]['asm_count_min'] = asm_count
                    if asm_count > coverage[filename][lineno]['asm_count_max']:
                        coverage[filename][lineno]['asm_count_max'] = asm_count
                    coverage[filename][lineno]['src_hits'] += src_hits
                    coverage[filename][lineno]['asm_hits'] += asm_hits

    def generate_coverage(coverage):
        for (file, counts) in coverage.items():
            annotated = "%s.coverage" % file.replace("/", "__")
            with open(annotated, 'w') as outfd:
                with open(file, 'r') as srcfd:
                    lineno = 1
                    for line in srcfd:
                        if lineno in counts:
                            prefix = "%s%s%s%s" % ("{:5d} ".format(counts[lineno]['src_hits']),
                                                   "{:5d} ".format(counts[lineno]['asm_hits']),
                                                   "{:3d} ".format(counts[lineno]['asm_count_max']),
                                                   "{:3d} ".format(counts[lineno]['asm_count_min']))
                        else:
                            prefix = 20 * " "
                        outfd.write("%s: %s" % (prefix, line))
                        lineno += 1
                print("Written coverage to %s" % annotated)

    dirs = get_test_dirs()
    files = get_result_files(dirs)
    coverage = init_coverage(files)
    # print(coverage)
    combine_results(files, coverage)
    # print(coverage)
    generate_coverage(coverage)
    
handler_process()
handler_combine()