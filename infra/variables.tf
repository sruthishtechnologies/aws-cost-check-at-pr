# variable.tf file
variable "aws_region" {
  default = "ap-south-2"
}

variable "ami_id" {
  default = "ami-0c02fb55956c7d316"
}

variable "instance_type" {
  default = "t4g.micro"
}

variable "root_volume_size" {
  default = 20
}
