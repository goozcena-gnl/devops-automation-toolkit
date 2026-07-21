resource "aws_security_group" "bad" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "example" {
  default = "safe"
}

locals {
  password = "SyntheticPassword123!"
}
