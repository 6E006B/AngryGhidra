import sys
import angr
import claripy
import json
from math import ceil
import time

EXPLORE_OPT = {}  # Explore options
REGISTERS = []  # Main registers of your binary
SYMVECTORS = []


def hook_function(state):
    for hook in EXPLORE_OPT["Hooks"]:
        if hook["address"] == str(hex(state.solver.eval(state.regs.ip))):
            for option, data in hook["registers"].items():
                if "sv" in data:
                    symbvector_length = int(data[2:], 0)
                    symbvector = claripy.BVS('symvector', symbvector_length * 8)
                    SYMVECTORS.append(symbvector)
                    data = symbvector
                else:
                    data = int(str(data), 0)
                if option in REGISTERS:
                    setattr(state.regs, option, data)


def main(file):
    with open(file, encoding='utf-8') as json_file:
        global EXPLORE_OPT
        EXPLORE_OPT = json.load(json_file)

    # Options parser
    # JSON can't handle with hex values, so we need to do it manually
    if "blank_state" in EXPLORE_OPT:
        blank_state = int(EXPLORE_OPT["blank_state"], 16)

    find = int(EXPLORE_OPT["find"], 16) if "find" in EXPLORE_OPT else None
    def find_function(state):
        if find is not None:
            if state.addr == find:
                return {state.addr}
        if "find_output" in EXPLORE_OPT:
            output = state.posix.dumps(1)
            for out in EXPLORE_OPT["find_output"]:
                if bytes(out, "utf8") in output:
                    return {state.addr}

    avoid = None
    if "avoid" in EXPLORE_OPT:
        avoid = [int(x, 16) for x in EXPLORE_OPT["avoid"].split(',')]
    if "avoid_output" in EXPLORE_OPT:
        def avoid_function(state):
            if avoid is not None:
                if state.addr in avoid:
                    return {state.addr}
            output = state.posix.dumps(1)
            for out in EXPLORE_OPT["avoid_output"]:
                if bytes(out, "utf8") in output:
                    return {state.addr}
    else:
        avoid_function = avoid

    # User can input hex or decimal value (argv length / symbolic memory length)
    argv = [EXPLORE_OPT["binary_file"]]
    if "Arguments" in EXPLORE_OPT:
        index = 1
        for arg, length in EXPLORE_OPT["Arguments"].items():
            argv.append(claripy.BVS("argv" + str(index), int(str(length), 0) * 8))
            index += 1
            
    if "Raw Binary" in EXPLORE_OPT:
        for bin_option, data in EXPLORE_OPT["Raw Binary"].items():
            if bin_option == "Arch":
                arch = data
            if bin_option == "Base":
                base_address = int(str(data), 0)
        p = angr.Project(EXPLORE_OPT["binary_file"],
                         load_options={'main_opts': {'backend': 'blob', 'arch': arch,
                                                     'base_addr': base_address}, 'auto_load_libs': EXPLORE_OPT["auto_load_libs"]})
    else:
        p = angr.Project(EXPLORE_OPT["binary_file"], load_options={"auto_load_libs": EXPLORE_OPT["auto_load_libs"]})

    global REGISTERS
    REGISTERS = p.arch.default_symbolic_registers

    if len(argv) > 1:
        state = p.factory.entry_state(args=argv)
    elif "blank_state" in locals():
        state = p.factory.blank_state(addr=blank_state)
    else:
        state = p.factory.entry_state()

    # Store symbolic vectors in memory
    if "Memory" in EXPLORE_OPT:
        Memory = {}
        for addr, length in EXPLORE_OPT["Memory"].items():
            symbmem_addr = int(addr, 16)
            symbmem_len = int(length, 0)
            Memory.update({symbmem_addr: symbmem_len})
            symb_vector = claripy.BVS('input', symbmem_len * 8)
            state.memory.store(symbmem_addr, symb_vector)

    # Write to memory
    if "Store" in EXPLORE_OPT:
        for addr, value in EXPLORE_OPT["Store"].items():
            store_addr = int(addr, 16)
            store_value = int(value, 16)
            store_length = ceil((len(value) - 2) / 2) if value.startswith("0x") else max(1, ceil(store_value / 8))
            state.memory.store(store_addr, state.solver.BVV(store_value, 8 * store_length))

    # Handle Symbolic Registers
    if "Registers" in EXPLORE_OPT:
        for register, data in EXPLORE_OPT["Registers"].items():
            if "sv" in data:
                symbvector_length = int(data[2:], 0)
                symbvector = claripy.BVS('symvector', symbvector_length * 8)
                SYMVECTORS.append(symbvector)
                data = symbvector
            else:
                data = int(str(data), 0)
            for REG in REGISTERS:
                if REG == register:
                    setattr(state.regs, register, data)
                    break

    # Handle Hooks
    if "Hooks" in EXPLORE_OPT:
        for hook in EXPLORE_OPT["Hooks"]:
            p.hook(int(hook["address"], 16), hook_function, length=int(hook["length"]))

    simgr = p.factory.simulation_manager(state)
    simgr.explore(find=find_function, avoid=avoid_function)

    solution = {}
    if simgr.found:
        found_path = simgr.found[0]

        win_sequence = ""
        for win_block in found_path.history.bbl_addrs.hardcopy:
            win_block = p.factory.block(win_block)
            addresses = win_block.instruction_addrs
            for address in addresses:
                win_sequence += hex(address) + ","
        win_sequence = win_sequence[:-1]
        solution["trace"] = win_sequence

        if len(argv) > 1:
            solution["argv"] = []
            for i in range(1, len(argv)):
                solution["argv"].append(str(found_path.solver.eval(argv[i], cast_to=bytes)))

        if "Memory" in locals() and len(Memory) != 0:
            solution["memory"] = {}
            for address, length in Memory.items():
                solution["memory"][hex(address)] = str(found_path.solver.eval(found_path.memory.load(address, length),
                                                                          cast_to=bytes))

        if len(SYMVECTORS) > 0:
            solution["symvectors"] = []
            for SV in SYMVECTORS:
                solution["symvectors"].append(str(found_path.solver.eval(SV, cast_to=bytes)))

        found_stdins = found_path.posix.stdin.content
        if len(found_stdins) > 0:
            stdin_bytes = b""
            for stdin in found_stdins:
                stdin_bytes += found_path.solver.eval(stdin[0], cast_to=bytes)
            solution["stdin"] = stdin_bytes.decode("utf8")
        if found_path.posix.stdout.content:
            solution["stdout"] = found_path.posix.dumps(1).decode('utf8')
    print(json.dumps(solution))
    return


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: *thisScript.py* angr_options.json")
        exit()
    file = sys.argv[1]
    main(file)
