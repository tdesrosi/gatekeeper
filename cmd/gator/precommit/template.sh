#!/bin/bash
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Precommit Hook for K8s Manifest Validation pre-CI/CD pipeline.
# Authors: Janine Bariuan and Thomas Desrosiers

# Unset CDPATH to restore default cd behavior. An exported CDPATH can
# cause cd to output the current directory to STDOUT.
unset CDPATH

# Send errors to STDERR
err() {
    printf "\n${red}> [$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*${nocolor}\n" >&2
}

# Colors and Formatting
bold=$(tput bold)
normal=$(tput sgr0)
green='\033[0;32m'
red='\033[0;31m'
nocolor='\033[0m'

# Only run pre-commit hook if any manifests are updated.
echo "> Checking for updated Kubernetes resources..."
updated_manifests=$(git diff --staged --stat | grep -o '.*\.yaml')

if [ -z "$updated_manifests" ]; then
    echo "> No updated resources found."
    exit 0
fi
echo "> Found updated resources. Validating..."

# Check if gator cli exists in the user's path.
if ! command -v gator &>/dev/null; then
    err 'Could not find gator. Please make sure it is installed AND in your $PATH'
    exit 1
fi

# Replace these strings with user's path/output preference.
JSON="json"
declare -a resources=("constraints-and-templates/oss-constraint-templates-library/" "demo/")
for resource in ${resources[@]}; do
    resource_string="$resource_string -f=$resource"
done

# Loop through updated yamls and run gator test against them.
IFS=$'' read -d '' -r -a files_to_check <<<"$updated_manifests"
for yaml in $files_to_check; do
    printf "\n> Checking file: $yaml"
    pass_or_fail=$(gator test $resource_string -f=$yaml --output=$JSON)
    if [[ -z $pass_or_fail ]] || [[ $pass_or_fail == 'null' ]]; then
        printf "\n> ${green}Congrats! No policy violations found.${nocolor}\n"
    else
        found_violations=true
        printf "\n> ${red}Violations found. See details below:\n\n${nocolor}" && echo $pass_or_fail
    fi
done

# Halt commit if violations found.
if [ $found_violations = true ]; then
    err "Some resources have policy violations. Halting Commit"
    exit 1
fi