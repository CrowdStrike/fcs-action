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
    cidr_blocks = ["0.0.0.0/0"]  # Should trigger security warning
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1d0"
  instance_type = "t2.micro"

  # No encryption specified - potential issue
  root_block_device {
    volume_type = "gp2"
    volume_size = 20
    # encrypted = false  # Should be encrypted
  }
}
