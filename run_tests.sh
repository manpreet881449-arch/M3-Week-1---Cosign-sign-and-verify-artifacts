#!/usr/bin/env bash
check() {
  result=$(opa eval -i "tests/$1" -d policy/ "data.deploy.allow" -f raw)
  if [ "$result" = "$2" ]; then echo "PASS $1"; else echo "FAIL $1 (got $result, want $2)"; fi
}
check input.json true
check bad.json false
check t1.json false
check t2.json false
check t3.json false
check t4.json false
