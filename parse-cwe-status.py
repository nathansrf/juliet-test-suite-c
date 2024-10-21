#!/usr/bin/env python3
import sys
import argparse
import re

cwe_desc = {
    "CWE121": "Stack Based Buffer Overflow",
    "CWE122": "Heap Based Buffer Overflow",
    "CWE124": "Buffer Underwrite",
    "CWE126": "Buffer Over-read",
    "CWE127": "Buffer Under-read",
    "CWE188": "Reliance on Data Memory Layout",
    "CWE190": "Integer Overflow or Wraparound",
    "CWE191": "Integer Underflow (Wrap or Wraparound)",
    "CWE244": "Improper Clearing of Heap Memory Before Release ('Heap Inspection')",
    "CWE401": "Improper Release of Memory Before Removing Last Reference ('Memory Leak')",
    "CWE415": "Double Free",
    "CWE416": "Use After Free",
    "CWE464": "Addition of Data Structure Sentinel",
    "CWE467": "Use of sizeof() on a Pointer Type",
    "CWE468": "Incorrect Pointer Scaling",
    "CWE469": "Use of Pointer Subtraction to Determine Size",
    "CWE562": "Return of Stack Variable Address",
    "CWE587": "Assignment of a Fixed Address to a Pointer",
    "CWE590": "Free of Memory not on the Heap",
    "CWE680": "Integer Overflow to Buffer Overflow",
    "CWE761": "Free of Pointer not at Start of Buffer",
    "CWE762": "Mismatched Memory Management Routines",
    "CWE789": "Uncontrolled Memory Allocation",
    "CWE843": "Access of Resource Using Incompatible Type ('Type Confusion')"
}

last_df_var = 84


def get_status_str(status: int) -> str:
    if status - 128 == 34:
        return "SIGPROT"
    if status - 128 == 6:
        return "SIGABRT"
    if status - 128 == 4:
        return "ILLEGAL_INST"
    if status == 124:
        return "TIMEOUT"
    if status == 139:
        return "SIGSEGV"
    if status == 0:
        return "OK"
    return str(status)


def update_dataflow_variant(status2dfvar: dict[int, list[int]], status: int, df_var: int) -> None:
    if status not in status2dfvar.keys():
        status2dfvar[status] = []
        for i in range(0, last_df_var + 1):
            status2dfvar[status].append(0)
    status2dfvar[status][df_var] = status2dfvar[status][df_var] + 1


def update_functional_variant(func_vars: dict[str, dict[int, int]], status: int, f_var: str) -> None:
    if f_var not in func_vars.keys():
        func_vars[f_var] = {}

    func_vars[f_var][status] = func_vars[f_var].get(status, 0) + 1


def do_parsing(filename: str) -> tuple[str, dict[int, list[int]], dict[str, dict[int, int]]]:
    with open(filename) as f:
        entries = [l for l in f]
        headline = entries[0]

        dataflow_stats: dict[int, list[int]] = {}
        functional_stats: dict[str, dict[int, int]] = {}

        entry_pattern = re.compile('(\S*)__(\S+)_(\d+)-\w* (\d*)\n')
        for e in entries[1:]:
            e_match = entry_pattern.match(e)
            if e_match:
                status = int(e_match.group(4))
                dataflow_var = int(e_match.group(3))
                functional_var = e_match.group(2)
                update_dataflow_variant(dataflow_stats, status, dataflow_var)
                update_functional_variant(functional_stats, status, functional_var)
            else:
                print("Failed to parse line:\n\t" + e, file=sys.stderr, end="")

        return (headline, dataflow_stats, functional_stats)


def print_exit_status_stats(status2dfvar: dict[int, list[int]]) -> None:
    print("\n===== EXIT STATUS =====")

    for status in sorted(status2dfvar.keys()):
        st_sum = sum(status2dfvar[status])
        print('{:10s} {:>5d}'.format(get_status_str(status), st_sum))

def print_as_csv(cwe: str, status2dfvar: dict[int, list[int]]) -> None:
    stats = {
        "OK": 0,
        "TIMEOUT": 0,
        "SIGSEGV": 0,
        "SIGPROT": 0,
        "SIGABRT": 0,
        "ILLEGAL_INST": 0,
    }

    # if the results has a relevant key, then update the value, otherwise it is left as zero
    for status in sorted(status2dfvar.keys()):
        st_sum = sum(status2dfvar[status])
        stats[get_status_str(status)] = st_sum

    csv_body=f"{cwe},{cwe_desc[cwe]},{stats['OK']},{stats['TIMEOUT']},{stats['SIGSEGV']},{stats['SIGPROT']},{stats['SIGABRT']},{stats['ILLEGAL_INST']}"
    print(csv_body)


def print_dataflow_stats(status2dfvar: dict[int, list[int]]) -> None:
    print("\n===== DATAFLOW VARIANTS =====")

    # Header
    print(" VAR ", end="")
    for status in sorted(status2dfvar.keys()):
        print("{:>10s}".format(get_status_str(status)), end="")
    print()

    # Rows
    for dfvar in range(1, last_df_var + 1):
        dfvar_sum = sum(status2dfvar[s][dfvar] for s in status2dfvar.keys())
        if dfvar_sum > 0:
            print(' {:2d}: '.format(dfvar), end="")
            for s in sorted(status2dfvar.keys()):
                print('{:>10d}'.format(status2dfvar[s][dfvar]), end="")
            print()


def print_functional_stats(exit_codes: list[int], func_stats: dict[str, dict[int, int]]) -> None:
    print("\n===== FUNCTIONAL VARIANTS =====")

    # Header
    print("{:30s}".format(""), end="")
    for s in exit_codes:
        print("{:>10s}".format(get_status_str(s)), end="")
    print()

    # Rows
    for fvar in func_stats.keys():
        print('{:30s}'.format(fvar), end="")
        for status in exit_codes:
            n = func_stats[fvar].get(status, 0)
            print('{:>10d}'.format(n), end="")
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse Juliet test cases run log")
    parser.add_argument("filename", type=str, help="path to file with run log, e.g. good.run")
    parser.add_argument("--csv", action="store_true", help="dump exit codes as CSV")
    parser.add_argument("--csv-with-header", action="store_true", help="display csv with header")
    args = parser.parse_args()

    # Define a regular expression pattern to match CWE<number>
    pattern = r'CWE(\d+)'
    match = re.search(pattern, args.filename)

    if match:
        cwe_number = match.group(0)
    else:
        exit()

    (headline, dataflow_stats, functional_stats) = do_parsing(args.filename)
    if args.csv_with_header:
        csv_header="cwe,description,ok,timeout,sigsegv,sigprot,sigabrt,illegal_inst"
        print(csv_header)
        print_as_csv(cwe_number, dataflow_stats)
        exit()
    if args.csv:
        print_as_csv(cwe_number, dataflow_stats)
        exit()
    print_exit_status_stats(dataflow_stats)
    print_dataflow_stats(dataflow_stats)
    print_functional_stats(sorted(dataflow_stats.keys()), functional_stats)
