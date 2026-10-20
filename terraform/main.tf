# terraform/main.tf
terraform {
  required_providers {
    docker = { source = "kreuzwerker/docker", version = "~> 3.0" }
  }
}
provider "docker" {}

resource "docker_image" "registry" {
  name = "registry:2"
}
resource "docker_container" "registry" {
  name  = "test-registry"
  image = docker_image.registry.image_id
  ports {
    internal = 5000
    external = 5001
  }
}
