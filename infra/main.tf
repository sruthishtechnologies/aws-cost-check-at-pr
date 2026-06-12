# main.tf file
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.50"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# EC2 instance creation for demo
resource "aws_instance" "demo" {
  ami           = var.ami_id
  instance_type = var.instance_type
  associate_public_ip_address = false

  root_block_device {
    volume_size = var.root_volume_size
    volume_type = "gp2"
  }

  tags = {
    Name        = "infracost-demo"
    Environment = "Dev"
    CostCenter  = "sre-training"
    Service     = "Demo-Service"
  }
}
