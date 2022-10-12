#!/bin/bash

function usage {
  echo "usage: ./.initalize.sh <ansible-version>"
}

if [[ $# -ne 1 ]]; then
  usage && exit 1
fi

python -m venv "ansible-${1}"

echo "source ${PWD}/ansible-${1}/bin/activate" > .env
echo "type deactivate &>/dev/null && deactivate" > .env.leave

source "ansible-${1}/bin/activate"

python -m pip install --upgrade pip
python -m pip install ansible==${1}

which ansible

ansible --version

# ----------------------------------

python3 -m pip install pynvim
