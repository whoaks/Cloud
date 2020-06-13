provider "aws" {
region = "ap-south-1"
profile = "aks07"
}


//creating key name and store in a variable 


variable "key" {
type = string
default = "key2"
}


//Key-Pair


resource "tls_private_key" "abc" {
algorithm = "RSA"
}
module "key_pair" {
source = "terraform-aws-modules/key-pair/aws"
key_name = var.key
public_key = tls_private_key.abc.public_key_openssh
}


// Creating Security-Groups


resource "aws_security_group" "security" {
name = "firewall"
description = "Allow HTTP and SSH"

ingress{
description = "SSH"
from_port =  22
to_port = 22
protocol = "tcp"
cidr_blocks = [ "0.0.0.0/0" ]
}

ingress{
description = "HTTP"
from_port =  80
to_port = 80
protocol = "tcp"
cidr_blocks = [ "0.0.0.0/0" ]
}

egress{
from_port =  0
to_port = 0
protocol = "-1"
cidr_blocks = [ "0.0.0.0/0" ]
}

tags = {
Name = "firewall"
}
}


//launch Instance


resource "aws_instance" "myinst" {
ami = "ami-0447a12f28fddb066"
instance_type = "t2.micro"
availability_zone = "ap-south-1a"
key_name = var.key
security_groups = [ aws_security_group.security.name ]

connection {
type = "ssh"
user= "ec2-user"
private_key = tls_private_key.abc.private_key_pem
host = aws_instance.myinst.public_ip
}

provisioner "remote-exec" {
inline = [
"sudo yum install httpd php git -y" ,
"sudo systemctl start httpd" ,
"sudo systemctl enable httpd" ,
]
}

tags = {
Name = "myos"
}
}


//Creating EBS Volume


resource "aws_ebs_volume" "ebs" {
availability_zone = aws_instance.myinst.availability_zone
size = 1
tags = {
Name = "vol"
}
}


//EBS volume attachment to Instance 


resource "aws_volume_attachment" "ebs_att" {
device_name = "/dev/sdd"
volume_id = aws_ebs_volume.ebs.id
instance_id = aws_instance.myinst.id
force_detach = true
}

output "go" {
value = aws_instance.myinst.public_ip
}

resource "null_resource" "res1" {
depends_on = [
aws_volume_attachment.ebs_att, 
]

connection {
type = "ssh"
user= "ec2-user"
private_key = tls_private_key.abc.private_key_pem
host = aws_instance.myinst.public_ip
}

provisioner "remote-exec" {
    inline = [
      "sudo mkfs.ext4  /dev/xvdd",
      "sudo mount  /dev/xvdd  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/whoaks/Cloud.git /var/www/html/"
    ]
  }
}

//Creating S3 Bucket


resource "aws_s3_bucket" "bucket" {

bucket = "aks4321"
acl = "public-read"
force_destroy = true
policy = <<EOF
{
  "Id": "MakePublic",
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetObject"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::aks4321/*",
      "Principal": "*"
    }
  ]
}
EOF


tags = {
Name = "aks4321"
}
}

 
//Block Public Access


resource "aws_s3_bucket_public_access_block" "s3block" {

bucket = aws_s3_bucket.bucket.id
block_public_policy = true
}

locals {
s3_origin_id = "S3-${aws_s3_bucket.bucket.bucket}"
}


//Creation Of CloudFront


resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
comment = "bucket_aks"
}

resource "aws_cloudfront_distribution" "cloudfront" {
    origin {
        domain_name = aws_s3_bucket.bucket.bucket_regional_domain_name
        origin_id = local.s3_origin_id
 
        s3_origin_config {

origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
}
}
 enabled = true
is_ipv6_enabled = true
comment = "access"


    default_cache_behavior {
        allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = local.s3_origin_id

        # Forward all query strings, cookies and headers
        forwarded_values {
            query_string = false
        
        cookies {
	forward = "none"
            }
        }

        viewer_protocol_policy = "allow-all"
        min_ttl = 0
        default_ttl = 3600
        max_ttl = 86400
    }
# Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }
    # Restricts who is able to access this content
    restrictions {
        geo_restriction {
            # type of restriction, blacklist, whitelist or none
            restriction_type = "none"
        }
    }

    # SSL certificate for the service.
    viewer_certificate {
        cloudfront_default_certificate = true
    }
retain_on_delete = true

}


//Locally Executing Command for WebHosting


resource "null_resource" "res2" {
depends_on = [
aws_cloudfront_distribution.cloudfront, 
]

provisioner "local-exec" {
command = "start chrome ${aws_instance.myinst.public_ip}"
}
}


//Access to IAM


resource "aws_iam_role" "codepipeline_role" {
  name = "task"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "codepipeline.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "codepipeline_policy" {
  name = "codepipeline_policy"
  role = "${aws_iam_role.codepipeline_role.id}"

 policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect":"Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetBucketVersioning",
        "s3:PutObject"
      ],
      "Resource": [
        "${aws_s3_bucket.bucket.arn}",
        "${aws_s3_bucket.bucket.arn}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codebuild:BatchGetBuilds",
        "codebuild:StartBuild"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

//CodePipeline

resource "aws_codepipeline" "codepipeline" {
  name     = "diyaksh"
  role_arn = "${aws_iam_role.codepipeline_role.arn}"


   artifact_store {
    location = "${aws_s3_bucket.bucket.bucket}"
    type     = "S3"
	}
	 
	 stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "ThirdParty"
      provider         = "GitHub"
      version          = "1"
      output_artifacts = ["SourceArtifacts"]
configuration = {
        Owner  = "aks4321"
        Repo   = "task1"
        Branch = "master"
	OAuthToken = "a962d286561fb7eeae716f2ecee9d258ac141042"        
      }
    }
  }

  stage {
    name = "Deploy"

    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "S3"
      version         = "1"
      input_artifacts = ["SourceArtifacts"]	
		configuration = {
        BucketName = "${aws_s3_bucket.bucket.bucket}"
        Extract = "true"
      }
      
    }
  }
}

//Special thanks to Vimal Daga Sir