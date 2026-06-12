# main.tf file
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# EC2 instance creation
#resource "aws_instance" "demo" {
#  ami           = var.ami_id
#  instance_type = var.instance_type
#
#  root_block_device {
#    volume_size = var.root_volume_size
#    volume_type = "gp3"
#  }
#
#  tags = {
#    Name        = "infracost-demo"
#    Environment = "dev"
#    CostCenter  = "sre-training"
#  }
#}
