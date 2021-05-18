#!/bin/bash
# (c) Artur.Klauser@computer.org
#
# This script installs support for building multi-architecture docker images
# with docker buildx on CI/CD pipelines like Github Actions or Travis. It is
# assumed that you start of with a fresh VM every time you run this and have to
# install everything necessary to support 'docker buildx build' from scratch.
#
# Example usage in Travis stage:
#
# jobs:
#   include:
#     - stage: Deploy docker image
#       script:
#         - source ./multi-arch-docker-ci.sh
#         - set -ex; build_ci_images::main; set +x
#
#  Platforms: linux/amd64, linux/arm64, linux/riscv64, linux/ppc64le,
#  linux/s390x, linux/386, linux/arm/v7, linux/arm/v6
# More information about Linux environment constraints can be found at:
# https://nexus.eddiesinentropy.net/2020/01/12/Building-Multi-architecture-Docker-Images-With-Buildx/

# Setup ci environment

function _version() {
  printf '%02d' $(echo "$1" | tr . ' ' | sed -e 's/ 0*/ /g') 2>/dev/null
}

function setup_ci_environment::install_docker_buildx() {
  # Check kernel version.
  local -r kernel_version="$(uname -r)"
  if [[ "$(_version "$kernel_version")" < "$(_version '4.8')" ]]; then
    echo "Kernel $kernel_version too old - need >= 4.8."
    exit 1
  fi

  # uninstall old versions
  sudo apt-get remove -y docker docker.io containerd runc

  ## Install up-to-date version of docker, with buildx support.
  # # Set up the repository
  # sudo apt-get update
  # sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
  # # Add Docker’s official GPG key
  # curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  # echo \
  # "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  # $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  # # Install Docker Engine
  # sudo apt-get update
  # sudo apt-get install -y docker-ce docker-ce-cli containerd.io

  # Enable docker daemon experimental support (for 'docker pull --platform').
  local -r config='/etc/docker/daemon.json'
  if [[ -e "$config" ]]; then
   sudo sed -i -e 's/{/{ "experimental": true, /' "$config"
  else
   echo '{ "experimental": true }' | sudo tee "$config"
  fi
  sudo systemctl restart docker

  # Install QEMU multi-architecture support for docker buildx.
  docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

  # Enable docker CLI experimental support (for 'docker buildx').
  export DOCKER_CLI_EXPERIMENTAL=enabled
  # Instantiate docker buildx builder with multi-architecture support.
  docker buildx create --name mybuilder
  docker buildx use mybuilder
  # Start up buildx and verify that all is OK.
  docker buildx inspect --bootstrap
}

# Log in to Docker Hub for deployment.
# Env:
#   DOCKER_USERNAME ... user name of Docker Hub account
#   DOCKER_PASSWORD ... password of Docker Hub account
function setup_ci_environment::login_to_docker_hub() {
  echo "$DOCKER_PASSWORD" | docker login --username "$DOCKER_USERNAME" --password-stdin

}

# Run buildx build and push.
# Env:
#   DOCKER_PLATFORMS ... space separated list of Docker platforms to build.
# Args:
#   Optional additional arguments for 'docker buildx build'.
function build_ci_images::buildx() {
  docker buildx build \
    --platform "${DOCKER_PLATFORMS// /,}" \
    --push \
    --progress plain \
    -f Dockerfile.multi-arch \
    "$@" \
    .
}

# Build and push docker images for all tags.
# Env:
#   DOCKER_PLATFORMS ... space separated list of Docker platforms to build.
#   DOCKER_BASE ........ docker image base name to build
#   TAGS ............... space separated list of docker image tags to build.
function build_ci_images::build_and_push_all() {
  for tag in $TAGS; do
    build_ci_images::buildx -t "$DOCKER_BASE:$tag"
  done
}

# Test all pushed docker images.
# Env:
#   DOCKER_PLATFORMS ... space separated list of Docker platforms to test.
#   DOCKER_BASE ........ docker image base name to test
#   TAGS ............... space separated list of docker image tags to test.
function build_ci_images::test_all() {
  for platform in $DOCKER_PLATFORMS; do
    for tag in $TAGS; do
      image="${DOCKER_BASE}:${tag}"
      msg="Testing docker image $image on platform $platform"
      line="${msg//?/=}"
      printf '\n%s\n%s\n%s\n' "\n${line}" "${msg}" "${line}"
      docker pull -q --platform "$platform" "$image"

      echo -n "Image architecture: "
      docker run --rm --entrypoint /bin/sh "$image" -c 'uname -m'

      # Run test on the built image.
      #docker run --rm  --entrypoint [] "$image" command yarn version
    done
      
  done
}

# Setup ci environment
function setup_ci_environment::main() {
  cp $DOCKERFILE Dockerfile.multi-arch
  # setup_ci_environment::install_docker_buildx
  setup_ci_environment::login_to_docker_hub
}

# Build images
function build_ci_images::main() {
  # Set platforms to build.
  export DOCKER_BASE=${TRAVIS_REPO_SLUG}
  build_ci_images::build_and_push_all
  #build_ci_images::test_all
}
