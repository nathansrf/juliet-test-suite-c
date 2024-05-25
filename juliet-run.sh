#!/bin/sh

# the first parameter specifies a non-default timeout duration
# the second parameter specifies the path of a library to LD_CHERI_PRELOAD when running test cases

# this script will run all good and bad tests in the bin subdirectory and write
# the names of the tests and their return codes into the files "good.run" and
# "bad.run". all tests are run with a timeout so that tests requiring input
# terminate quickly with return code 124.

ulimit -c 0

usage() {
  echo "$0 -c CWE_NUMBER -t TIMEOUT -p PRE_LOAD_LIB_PATH -i INPUT_FILE_PATH -q QEMU_COMMAND"
}

# default arg values
SCRIPT_DIR=$(dirname $(realpath "$0"))
TIMEOUT="1s"
INPUT_FILE="/tmp/in.txt"

while getopts "hc:t:p:i:q:" opt; do
  case $opt in
    c) 
      CWE="$OPTARG"
      ;;
    t)
      TIMEOUT="$OPTARG"
      ;;
    p)
      PRELOAD_PATH="$OPTARG"
      ;;
    i)
      INPUT_FILE="$OPTARG"
      ;;
    q)
      QEMU="$OPTARG"
      ;;
    h)
      usage
      exit 1
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

if [ $OPTIND -eq 1 ]; then 
  usage
  exit 1
fi

touch $INPUT_FILE

# parameter 1: the CWE directory corresponding to the tests
# parameter 2: the type of tests to run (should be "good" or "bad")
run_tests()
{
  local CWE_DIRECTORY="$1"
  local TEST_TYPE="$2"
  local TYPE_PATH="${CWE_DIRECTORY}/${TEST_TYPE}"

  local PREV_CWD=$(pwd)
  cd "${CWE_DIRECTORY}" # change directory in case of test-produced output files

  echo "========== STARTING TEST ${TYPE_PATH} $(date) ==========" >> "${TYPE_PATH}.run"
  for TESTCASE in $(ls -1 "${TYPE_PATH}"); do
    local TESTCASE_PATH="${TYPE_PATH}/${TESTCASE}"

    if [ ! -z "${PRELOAD_PATH}" ]
    then
      if [ ! -z "${QEMU}" ]; then
        timeout ${TIMEOUT} ${QEMU} -E LD_PRELOAD=${PRELOAD_PATH} ${TESTCASE_PATH} < ${INPUT_FILE}
      else
        timeout ${TIMEOUT} env LD_PRELOAD=${PRELOAD_PATH} ${TESTCASE_PATH} < ${INPUT_FILE}
      fi
    else
      if [ ! -z "${QEMU}" ]; then
        timeout ${TIMEOUT} ${QEMU} ${TESTCASE_PATH} < ${INPUT_FILE}
      else
        timeout ${TIMEOUT} ${TESTCASE_PATH} < ${INPUT_FILE}
      fi
    fi

    echo "${TESTCASE_PATH} $?" >> "${TYPE_PATH}.run"
  done

  cd "${PREV_CWD}"
}

run_tests "${SCRIPT_DIR}/CWE$CWE" "good"
run_tests "${SCRIPT_DIR}/CWE$CWE" "bad"
