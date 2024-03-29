<!--
Describe the change in summary section, including rationale and design decisions.
Include "Fixes #nnn" if you are fixing an existing issue.

In "Test Plan" provide enough detail on how you plan to test this PR so that a reviewer can validate your tests. If our CI covers sufficient tests, then state which tests cover the change.

If you have more information you want to add, write them in "Additional
Information" section. This is usually used to help others understand your
motivation behind this change. A step-by-step reproduction of the problem is
helpful if there is no related issue.
-->

##### Summary

##### Test Plan
1. Clone this branch
2. Run the following commands:
```sh
# git submodule update --init --recursive
# make clean; make
# cd src/tests
# sh run_tests.sh
```
3. Verify that you do not have any `libbpf` error inside `error.log`.

##### Additional information

| Linux Distribution |   Environment  |Kernel Version |    Error    | Success |
|--------------------|----------------|---------------|-------------|---------|
| LINUX DISTRIBUTION  | Bare metal/VM  | uname -r      |             |         |
