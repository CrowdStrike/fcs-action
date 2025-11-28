# Sample Terraform file with potential security issues
resource "aws_s3_bucket" "example" {
  bucket = "my-insecure-bucket"

  # This should trigger security findings
  acl = "public-read"
}

resource "aws_security_group" "web" {
  name_prefix = "web-"

  # Overly permissive security group
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    # Should trigger security warning
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "TESTING"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1d0"
  instance_type = "t2.micro"

  associate_public_ip_address = false
  monitoring                  = true
  ebs_optimized              = true
  vpc_security_group_ids     = [aws_security_group.web.id]

  tags = {
    Name        = "web-instance"
    Environment = "development"
    Purpose     = "web-server"
  }

  root_block_device {
    volume_type = "gp2"
    volume_size = 20
  }
}
