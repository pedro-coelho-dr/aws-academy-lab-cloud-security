# AWS Academy lab: Securing and Monitoring Resources with AWS

This project is part of the `Cloud Infrastructure Security Course` in the `Cybersecurity Specialization` at [CESAR School](https://cesar.school/).

The tasks are from `AWS Academy` lab: `Securing and Monitoring Resources with AWS`. It focus on securing AWS resources such as S3, VPCs, and implementing encryption with AWS KMS, along with monitoring and logging using AWS CloudTrail, CloudWatch, and AWS Config.

Student: `Pedro Coelho`  
Instructor: `Ioram Sette`

**Table of Contents**

- [AWS Academy lab: Securing and Monitoring Resources with AWS](#aws-academy-lab-securing-and-monitoring-resources-with-aws)
  - [Phase 1: Securing Data in Amazon S3](#phase-1-securing-data-in-amazon-s3)
    - [Task 1.1: Create a bucket, apply a bucket policy, and test access](#task-11-create-a-bucket-apply-a-bucket-policy-and-test-access)
    - [Task 1.2: Enable versioning and object-level logging on a bucket](#task-12-enable-versioning-and-object-level-logging-on-a-bucket)
    - [Task 1.3: Implement the S3 Inventory feature on a bucket](#task-13-implement-the-s3-inventory-feature-on-a-bucket)
    - [Task 1.4: Confirm that versioning works as intended](#task-14-confirm-that-versioning-works-as-intended)
    - [Task 1.5: Confirm object-level logging and query the access logs by using Athena](#task-15-confirm-object-level-logging-and-query-the-access-logs-by-using-athena)
  - [Phase 2: Securing VPCs](#phase-2-securing-vpcs)
    - [Task 2.1: Review LabVPC and its associated resources](#task-21-review-labvpc-and-its-associated-resources)
    - [Task 2.2: Create a VPC flow log](#task-22-create-a-vpc-flow-log)
    - [Task 2.3: Access the WebServer instance from the internet and review VPC flow logs in CloudWatch](#task-23-access-the-webserver-instance-from-the-internet-and-review-vpc-flow-logs-in-cloudwatch)
    - [Task 2.4: Configure route table and security group settings](#task-24-configure-route-table-and-security-group-settings)
    - [Task 2.5: Secure the WebServerSubnet with a network ACL](#task-25-secure-the-webserversubnet-with-a-network-acl)
    - [Task 2.6: Review NetworkFirewallVPC and its associated resources](#task-26-review-networkfirewallvpc-and-its-associated-resources)
    - [Task 2.7: Create a network firewall](#task-27-create-a-network-firewall)
    - [Task 2.8: Create route tables](#task-28-create-route-tables)
    - [Task 2.9: Configure logging for the network firewall](#task-29-configure-logging-for-the-network-firewall)
    - [Task 2.10: Configure the firewall policy and test access](#task-210-configure-the-firewall-policy-and-test-access)
  - [Phase 3: Securing AWS resources by using AWS KMS](#phase-3-securing-aws-resources-by-using-aws-kms)
    - [Task 3.1: Create a customer managed key and configure key rotation](#task-31-create-a-customer-managed-key-and-configure-key-rotation)
    - [Task 3.2: Update the AWS KMS key policy and analyze an IAM policy](#task-32-update-the-aws-kms-key-policy-and-analyze-an-iam-policy)
    - [Task 3.3: Use AWS KMS to encrypt data in Amazon S3](#task-33-use-aws-kms-to-encrypt-data-in-amazon-s3)
    - [Task 3.4: Use AWS KMS to encrypt the root volume of an EC2 instance](#task-34-use-aws-kms-to-encrypt-the-root-volume-of-an-ec2-instance)
    - [Task 3.5: Use AWS KMS envelope encryption to encrypt data in place](#task-35-use-aws-kms-envelope-encryption-to-encrypt-data-in-place)
    - [Task 3.6: Use AWS KMS to encrypt a Secrets Manager secret](#task-36-use-aws-kms-to-encrypt-a-secrets-manager-secret)
  - [Phase 4: Monitoring and logging](#phase-4-monitoring-and-logging)
    - [Task 4.1: Use CloudTrail to record Amazon S3 API calls](#task-41-use-cloudtrail-to-record-amazon-s3-api-calls)
    - [Task 4.2: Use CloudWatch Logs to monitor secure logs](#task-42-use-cloudwatch-logs-to-monitor-secure-logs)
    - [Task 4.3: Create a CloudWatch alarm to send notifications for security incidents](#task-43-create-a-cloudwatch-alarm-to-send-notifications-for-security-incidents)
    - [Task 4.4: Configure AWS Config to assess security settings and remediate the configuration of AWS resources](#task-44-configure-aws-config-to-assess-security-settings-and-remediate-the-configuration-of-aws-resources)


## Phase 1: Securing Data in Amazon S3

### Task 1.1: Create a bucket, apply a bucket policy, and test access


![alt text](img/image.png)

![alt text](img/image-1.png)

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowSpecificPrincipals",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::518337386052:role/voclabs",
                    "arn:aws:iam::518337386052:user/sofia",
                    "arn:aws:iam::518337386052:user/paulo"
                ]
            },
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::data-bucket-01f5a3e8ab0aef64d",
                "arn:aws:s3:::data-bucket-01f5a3e8ab0aef64d/*"
            ],
            "Condition": {
                "ArnEquals": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::518337386052:user/paulo",
                        "arn:aws:iam::518337386052:user/sofia",
                        "arn:aws:iam::518337386052:role/voclabs"
                    ]
                }
            }
        },
        {
            "Sid": "DenyOtherPrincipals",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::data-bucket-01f5a3e8ab0aef64d",
                "arn:aws:s3:::data-bucket-01f5a3e8ab0aef64d/*"
            ],
            "Condition": {
                "ArnNotEquals": {
                    "aws:PrincipalArn": [
                        "arn:aws:iam::518337386052:user/paulo",
                        "arn:aws:iam::518337386052:user/sofia",
                        "arn:aws:iam::518337386052:role/voclabs"
                    ]
                }
            }
        }
    ]
}
```

![alt text](img/image-2.png)  

![alt text](img/image-3.png)  

### Task 1.2: Enable versioning and object-level logging on a bucket

![alt text](img/image-4.png)


![alt text](img/image-5.png)


![alt text](img/image-6.png)


### Task 1.3: Implement the S3 Inventory feature on a bucket

![alt text](img/image-7.png)

### Task 1.4: Confirm that versioning works as intended


![alt text](img/image-8.png)

![alt text](img/image-3.png)  

### Task 1.5: Confirm object-level logging and query the access logs by using Athena

![alt text](img/image-9.png)

![alt text](img/image-10.png)

![alt text](img/image-11.png)

## Phase 2: Securing VPCs
### Task 2.1: Review LabVPC and its associated resources  
![alt text](img/image-13.png)  
![alt text](img/image-12.png)  
![alt text](img/image-15.png)  
![alt text](img/image-14.png)  

### Task 2.2: Create a VPC flow log
![alt text](img/image-16.png)


### Task 2.3: Access the WebServer instance from the internet and review VPC flow logs in CloudWatch

![alt text](img/image-18.png)  

![alt text](img/image-19.png)


### Task 2.4: Configure route table and security group settings

![alt text](img/image-20.png)  

![alt text](img/image-22.png)  

![alt text](img/image-23.png)  


### Task 2.5: Secure the WebServerSubnet with a network ACL

![alt text](img/image-24.png)  

![alt text](img/image-25.png)  

### Task 2.6: Review NetworkFirewallVPC and its associated resources

![alt text](img/image-27.png)  

![alt text](img/image-28.png)

![alt text](img/image-29.png)

### Task 2.7: Create a network firewall

![alt text](img/image-30.png)  

### Task 2.8: Create route tables

![alt text](img/image-31.png)  

![alt text](img/image-32.png)  

![alt text](img/image-33.png)  

### Task 2.9: Configure logging for the network firewall

![alt text](img/image-34.png)

![alt text](img/image-35.png)

### Task 2.10: Configure the firewall policy and test access

![alt text](img/image-36.png)

![alt text](img/image-37.png)

![alt text](img/image-38.png)  

![alt text](img/image-39.png)

## Phase 3: Securing AWS resources by using AWS KMS
### Task 3.1: Create a customer managed key and configure key rotation

![alt text](img/image-40.png)  

![alt text](img/image-41.png)

### Task 3.2: Update the AWS KMS key policy and analyze an IAM policy

![alt text](img/image-42.png)  

![alt text](img/image-43.png)

![alt text](img/image-44.png)

### Task 3.3: Use AWS KMS to encrypt data in Amazon S3

![alt text](img/image-45.png)  

![alt text](img/image-46.png)

![alt text](img/image-47.png)

### Task 3.4: Use AWS KMS to encrypt the root volume of an EC2 instance

![alt text](img/image-48.png)

### Task 3.5: Use AWS KMS envelope encryption to encrypt data in place

![alt text](img/image-50.png)

![alt text](img/image-51.png)

![alt text](img/image-52.png)  

![alt text](img/image-53.png)  


### Task 3.6: Use AWS KMS to encrypt a Secrets Manager secret

![alt text](img/image-54.png)

## Phase 4: Monitoring and logging
### Task 4.1: Use CloudTrail to record Amazon S3 API calls

![alt text](img/image-55.png)

![alt text](img/image-56.png)

![alt text](img/image-57.png)

![alt text](img/image-58.png)

### Task 4.2: Use CloudWatch Logs to monitor secure logs

![alt text](img/image-59.png)

![alt text](img/image-61.png)

![alt text](img/image-62.png)

![alt text](img/image-63.png)

![alt text](img/image-64.png)


### Task 4.3: Create a CloudWatch alarm to send notifications for security incidents

![alt text](img/image-66.png)

![alt text](img/image-65.png)

![alt text](img/image-67.png)

![alt text](img/image-68.png)

![alt text](img/image-69.png)

### Task 4.4: Configure AWS Config to assess security settings and remediate the configuration of AWS resources

![alt text](img/image-71.png)

![alt text](img/image-72.png)

![alt text](img/image-73.png)

![alt text](img/image-75.png)

![alt text](img/image-76.png)