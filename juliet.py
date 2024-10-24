#!/usr/bin/env python3


import sys, os, re, argparse, shutil, subprocess, pathlib


root_dir = str(pathlib.Path(__file__).parent)


def juliet_print(string):
    print("========== " + string + " ==========")


def clean(path):
    try:
        os.remove(path + "/CMakeLists.txt")
        os.remove(path + "/CMakeCache.txt")
        os.remove(path + "/cmake_install.cmake")
        os.remove(path + "/Makefile")
        shutil.rmtree(path + "/CMakeFiles")
    except OSError:
        pass


def generate(path, output_dir, keep_going, c_compiler=None, cxx_compiler=None):
    shutil.copy(root_dir + "/CMakeLists.txt", path)
    if c_compiler is None or cxx_compiler is None:
        retcode = subprocess.Popen(["cmake", "-DOUTPUT_DIR:STRING=" + output_dir, "."], cwd=path).wait()
    else:
        retcode = subprocess.Popen(["cmake", "-DCMAKE_C_COMPILER="+c_compiler, "-DCMAKE_CXX_COMPILER="+cxx_compiler, "-DOUTPUT_DIR:STRING=" + output_dir, "."], cwd=path).wait()
    if retcode != 0 and not keep_going:
        juliet_print("error generating " + path + " - stopping")
        exit()


def make(path, keep_going):
    if keep_going:
        subprocess.Popen(["make", "-j16", "-k"], cwd=path).wait()
    else:
        retcode = subprocess.Popen(["make", "-j16"], cwd=path).wait()
        if retcode != 0:
            juliet_print("error making " + path + " - stopping")
            exit()


def run(CWE, output_dir, timeout, with_qemu=False, qemu_path=None):
    if with_qemu:
        subprocess.Popen([root_dir + "/" + output_dir + "/juliet-run.sh", "-c", str(CWE), "-t", timeout, "-q", qemu_path]).wait()
    else:
        subprocess.Popen([root_dir + "/" + output_dir + "/juliet-run.sh", "-c", str(CWE), "-t", timeout]).wait()

def run_with_library(CWE, output_dir, lib_path, timeout, with_qemu=False, qemu_path=None):
    if with_qemu:
         subprocess.Popen([root_dir + "/" + output_dir + "/juliet-run.sh", "-c", str(CWE), "-p", lib_path, "-t", timeout, "-q", str(qemu_path)]).wait()
    else:
        subprocess.Popen([root_dir + "/" + output_dir + "/juliet-run.sh", "-c", str(CWE), "-p", lib_path, "-t", timeout]).wait()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="build and run Juliet test cases for targeted CWEs")
    parser.add_argument("CWEs", metavar="N", type=int, nargs="*", help="a CWE number to target")
    parser.add_argument("-c", "--clean", action="store_true", help="clean all CMake and make files for the targeted CWEs")
    parser.add_argument("-g", "--generate", action="store_true", help="use CMake to generate Makefiles for the targeted CWEs")
    parser.add_argument("-m", "--make", action="store_true", help="use make to build test cases for the targeted CWES")
    parser.add_argument("-r", "--run", action="store_true", help="run tests for the targeted CWEs")
    parser.add_argument("-a", "--all", action="store_true", help="target all CWEs")
    parser.add_argument("-l", "--library", action="store", help="Path to dynamic library for use in test case (uses LD_PRELOAD)")
    parser.add_argument("-k", "--keep-going", action="store_true", help="keep going in case of build failures")
    parser.add_argument("-o", "--output-dir", action="store", default="bin", help="specify the output directory relative to the directory containing this script (default: bin)")
    parser.add_argument("-t", "--run-timeout", action="store", default="1", type=float, help="specify the default test run timeout in seconds (type: float, default: 1)")
    parser.add_argument("-q", "--qemu", action="store_true", help="enable running of test in usermode QEMU")
    parser.add_argument("--qemu_path", action="store", default="qemu-aarch64", type=str, help="path to qemu binary (default 'qemu-aarch64')")
    parser.add_argument("--c-compiler", action="store", default="", type=str, help="name of c compiler, e.g. clang-15")
    parser.add_argument("--cxx-compiler", action="store", default="", type=str, help="name of c++ compiler, e.g. clang++15")
    args = parser.parse_args()
    args.CWEs = set(args.CWEs)

    if len(sys.argv) == 1:
        parser.print_help()
        parser.exit()

    testcases = root_dir + "/testcases"
    if not os.path.exists(testcases):
        juliet_print("no testcases directory")
        exit()

    if args.generate and not os.path.exists(root_dir + "/CMakeLists.txt"):
        juliet_print("no CMakeLists.txt")
        exit()

    if args.run and not os.path.exists(root_dir + "/juliet-run.sh"):
        juliet_print("no juliet-run.sh")
        exit()

    for subdir in os.listdir(testcases):
        match = re.search("^CWE(\d+)", subdir)
        if match != None:
            parsed_CWE = int(match.group(1))
            if (parsed_CWE in args.CWEs) or args.all:
                path = testcases + "/" + subdir
                if args.clean:
                    juliet_print("cleaning " + path)
                    clean(path)
                if args.generate:
                    juliet_print("generating " + path)
                    if args.c_compiler and args.cxx_compiler:
                        generate(path, args.output_dir, args.keep_going, c_compiler=args.c_compiler, cxx_compiler=args.cxx_compiler)
                    else:
                        generate(path, args.output_dir, args.keep_going)
                if args.make:
                    juliet_print("making " + path)
                    make(path, args.keep_going)
                if args.run:
                    juliet_print("running " + path)
                    if args.library:
                        run_with_library(parsed_CWE, args.output_dir, args.library, str(args.run_timeout) + "s", with_qemu=args.qemu, qemu_path=args.qemu_path)
                    else:
                        run(parsed_CWE, args.output_dir, str(args.run_timeout) + "s", with_qemu=args.qemu, qemu_path=args.qemu_path)
