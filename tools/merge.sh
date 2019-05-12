#!/bin/bash

set -e
set -u

function error {
  echo -n -e '\e[31m\e[1m'
  echo -n "ERROR:" "$@"
  echo -e '\e[0m'
}

CURL="curl --fail --show-error --silent"

if [[ -e ~/.gittoken ]]; then
  CURL+=" -u $(cat ~/.gittoken):"
fi

if [[ -n $(git status -su) ]]; then
  error 'Current tree is dirty, aborting merge request.'
  git status
  exit -1
fi

git fetch
if [[ $(git rev-parse HEAD) != $(git rev-parse @{u}) ]]; then
  error 'Current branch diverged from origin, aborting merge request.'
  git status
  exit -1
fi

BRANCH=$(git rev-parse --abbrev-ref HEAD)
PULL_URL=$(${CURL} https://api.github.com/repos/sarum90/qjsonrs/pulls \
  | jq -r --arg branch "${BRANCH}" \
  '.[] | {url: .url, branch: .head.ref} | select(.branch == $branch) | .url')

TMPDIR=$(mktemp -d)
function finish {
  rm -rf "${TMPDIR}"
}
trap finish EXIT

PR_JSON_FILE="${TMPDIR}/pr.json"
${CURL} "${PULL_URL}" > "${PR_JSON_FILE}"

COMMIT_FILE="${TMPDIR}/COMMIT_EDITMSG"
TITLE=$(jq -r .title "${PR_JSON_FILE}")
BODY=$(jq -r .body "${PR_JSON_FILE}")
BASE=$(jq -r .base.ref "${PR_JSON_FILE}")
COMMIT_SHA=$(jq -r .head.sha "${PR_JSON_FILE}")
echo here
STATUS=$(${CURL} https://api.github.com/repos/sarum90/qjsonrs/commits/${COMMIT_SHA}/status | jq -r '.state')
if [[ ${STATUS} == "pending" ]]; then
  echo "Current github status is pending."
  read -p "Do you want to wait til that completes [y/N]? " -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]
  then
    error "Will not merge pending branch"
    exit -1
  fi
  while [[ ${STATUS} == "pending" ]]; do
    echo "Waiting 5 sec... (CTRL-C is safe to do whenever)"
    sleep 5
    STATUS=$(${CURL} https://api.github.com/repos/sarum90/qjsonrs/commits/${COMMIT_SHA}/status | jq -r '.state')
    echo "New status: ${STATUS}"
  done
fi

if [[ ${STATUS} != "success" ]]; then
  error "Will not merge commit with status ${STATUS}, must be success"
  exit -1
fi

truncate -s 0 "${COMMIT_FILE}"
echo "${TITLE}" >> "${COMMIT_FILE}"
echo >> "${COMMIT_FILE}"
echo "${BODY}" | fold -w 80 -s >> "${COMMIT_FILE}"
"${EDITOR}" "${COMMIT_FILE}"
if [[ -z $(grep -v '^#' "${COMMIT_FILE}" | tr -d '[:space:]') ]]; then
  error "Aborting due to empty commit message"
  exit -1
fi
echo "Merging with commit message:"
echo "==="
cat "${COMMIT_FILE}"
echo "==="
read -p "Are you sure [y/N]? " -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
  error "Exit on user request"
  exit -1
fi

# Now we are changing working tree, be very explicit about it:
set -x

git checkout ${BASE}
git pull origin
git merge --squash --no-commit
git commit -F "${COMMIT_FILE}"
# git push origin
