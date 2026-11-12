# =============================================================
# StormGlass — reference target environment (v1)
# Same as v0 with ONE fix applied: the public web server now has
# its own role with no access to S3. Everything else is unchanged,
# so any difference in attack paths is caused by this fix alone.
# A deliberately imperfect fintech-shaped AWS environment.
# This is NOT deployed. It exists to be PLANNED, so the plan
# JSON becomes the first input to the StormGlass twin builder.
#
# The "sloppiness" (over-broad IAM, public exposure) is
# intentional: it gives the simulation engine real attack
# paths to find. Comment tags like #SG-FLAW mark them.
# =============================================================

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  # Local-only: never contact AWS. Lets `terraform plan` run
  # with no credentials and no real resources.
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  access_key                  = "mock"
  secret_key                  = "mock"
}

# ----- Network: one VPC, a public and a private subnet -------
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags = { Name = "sg-fintech-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  tags = { Name = "sg-public", tier = "public" }
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"
  tags = { Name = "sg-private", tier = "private" }
}

# ----- Security groups ---------------------------------------
resource "aws_security_group" "web" {
  name   = "stormglass-web"
  vpc_id = aws_vpc.main.id
  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    # SG-FLAW: SSH open to the whole internet, not just a bastion.
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "sg-web" }
}

resource "aws_security_group" "app" {
  name   = "stormglass-app"
  vpc_id = aws_vpc.main.id
  ingress {
    description     = "App port from web tier"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
  ingress {
    # SG-FLAW: app tier also reachable on SSH from the web tier,
    # widening lateral movement once the web box is owned.
    description     = "SSH from web tier"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "sg-app" }
}

# ----- Compute: web box (public) and app box (private) -------
resource "aws_instance" "web" {
  ami                    = "ami-0mock00000000000"
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id]
  # SG-FIX: the web server no longer shares the backend's role.
  iam_instance_profile   = aws_iam_instance_profile.web.name
  tags = { Name = "sg-web-01", role = "frontend" }
}

resource "aws_instance" "app" {
  ami                    = "ami-0mock00000000000"
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name
  tags = { Name = "sg-app-01", role = "backend" }
}

# ----- Data: the crown jewels --------------------------------
resource "aws_s3_bucket" "customer_records" {
  bucket = "sg-fintech-customer-records"
  tags   = { Name = "customer-records", sensitivity = "high" }
}

resource "aws_db_instance" "records" {
  identifier          = "sg-fintech-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  db_subnet_group_name = aws_db_subnet_group.main.name
  skip_final_snapshot = true
  tags = { Name = "sg-records-db", sensitivity = "high" }
}

resource "aws_db_subnet_group" "main" {
  name       = "sg-db-subnets"
  subnet_ids = [aws_subnet.private.id, aws_subnet.public.id]
}

# ----- Identity: roles with realistic over-permissioning -----
resource "aws_iam_role" "app" {
  name = "sg-app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = { Name = "sg-app-role" }
}

resource "aws_iam_instance_profile" "app" {
  name = "sg-app-profile"
  role = aws_iam_role.app.name
}

resource "aws_iam_role_policy" "app_policy" {
  name = "sg-app-policy"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      # SG-FLAW (still present): wildcard S3 access. Only the
      # backend server holds this role now.
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "*"
    }]
  })
}

# ----- SG-FIX: a separate, minimal role for the web server ---
resource "aws_iam_role" "web" {
  name = "sg-web-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = { Name = "sg-web-role" }
}

resource "aws_iam_instance_profile" "web" {
  name = "sg-web-profile"
  role = aws_iam_role.web.name
}

resource "aws_iam_role_policy" "web_policy" {
  name = "sg-web-policy"
  role = aws_iam_role.web.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      # The web server may write its own logs and nothing else.
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "*"
    }]
  })
}
