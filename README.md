# Cloudfront Drift Detector

Python tool to perform a comparison against a template from a CloudFormation Stack to a CloudFront Distribution's Configuration.


## Getting Started
These instructions will get a the tool up and running.

**NOTE:**  ***this tool is a work in progress and may not account for all possible cloudfront configuration options***
### Requirements
Tested and developed on Ubuntu 18.04.

AWS Requirements
* A CloudFormation stack that defines a CloudFront Resource
* CloudFormation IAM Permissions for 'GetTemplate'
* CloudFront IAM Permissions for 'GetDistribution'
* [AWS CLI authentication](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)
You will need the following packages installed
* python3
* [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html)
* [aws-cli](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)

## Usage

```detect-drift.py AEZ8EEWIUHAEF0 my-cloudformation-stack```

*or*

```detect-drift.py AEZ8EEWIUHAEF0  arn:aws:cloudformation:us-east-2:123456789012:stack/mystack-mynestedstack-sggfrhxhum7w/f449b250-b969-11e0-a185-5081d0136786 ```
```
usage: detect-drift.py [-h] cloudfront-distribution-id cloudformation-stack-id

AWS Drift Detector. This tool takes an uploaded CloudFormation stack and
compares its attached template to a CloudFront Distribution. It then reports
if it finds any drift in configuration

positional arguments:
  cloudfront-distribution-id
                        The ID for the CloudFront Distribution
  cloudformation-stack-id
                        The ID or Name for the CloudFormation Stack

optional arguments:
  -h, --help            show this help message and exit

Here may be dragons...
```
### Results
Here is an example comparing a CloudFormation stack against the cloudfront distribution it deployed
```
Status Report
------------------------------------------------------------------------------------
Resource Type: Comment
        Status: success
------------------------------------------------------------------------------------
Resource Type: DefaultRootObject
        Status: success
------------------------------------------------------------------------------------
Resource Type: HttpVersion
        Status: success
------------------------------------------------------------------------------------
Resource Type: IPV6Enabled
        Status: success
------------------------------------------------------------------------------------
Resource Type: PriceClass
        Status: success
------------------------------------------------------------------------------------
Resource Type: Enabled
        Status: success
------------------------------------------------------------------------------------
Resource Type: Aliases
        Status: success
------------------------------------------------------------------------------------
Resource Type: Logging
        Status: success         Message: Bucket
        Status: success         Message: Prefix
        Status: success         Message: IncludeCookies
------------------------------------------------------------------------------------
Resource Type: ViewerCertificate
        Status: success         Message: MinimumProtocolVersion
        Status: success         Message: SslSupportMethod
        Status: success         Message: AcmCertificateArn
------------------------------------------------------------------------------------
Resource Type: CustomErrorResponses
        Status: success         Message: ErrorCachingMinTTL
        Status: success         Message: ErrorCode
        Status: success         Message: ResponseCode
        Status: success         Message: ResponsePagePath
------------------------------------------------------------------------------------
Resource Type: Origins
        Status: success         Message: CustomOrigin: HTTPPort
        Status: success         Message: CustomOrigin: HTTPSPort
        Status: success         Message: CustomOrigin: OriginKeepaliveTimeout
        Status: success         Message: CustomOrigin: OriginReadTimeout
        Status: success         Message: CustomOrigin: OriginProtocolPolicy
        Status: success         Message: CustomOrigin: OriginSSLProtocols
------------------------------------------------------------------------------------
Resource Type: CacheBehaviors
        Status: success         Message: PathPattern
        Status: success         Message: TargetOriginId
        Status: success         Message: ViewerProtocolPolicy
        Status: success         Message: SmoothStreaming
        Status: success         Message: DefaultTTL
        Status: success         Message: MinTTL
        Status: success         Message: MaxTTL
        Status: success         Message: Compress
------------------------------------------------------------------------------------
Resource Type: DefaultCacheBehavior
        Status: success         Message: TargetOriginId
        Status: success         Message: Compress
        Status: success         Message: MinTTL
        Status: success         Message: MaxTTL
        Status: success         Message: DefaultTTL
        Status: success         Message: SmoothStreaming
        Status: success         Message: ViewerProtocolPolicy
        Status: success         Message: ForwardedValues QueryString
        Status: success         Message: AllowedMethod GET
        Status: success         Message: AllowedMethod HEAD
        Status: success         Message: AllowedMethod OPTIONS
```

And here are the results comparing the same CloudFormation stack against the wrong CloudFront Distribution.
```
Status Report
------------------------------------------------------------------------------------
Resource Type: Comment
        Status: failed          Message: No data from CloudFront
------------------------------------------------------------------------------------
Resource Type: DefaultRootObject
        Status: failed          Message: No data from CloudFront
------------------------------------------------------------------------------------
Resource Type: HttpVersion
        Status: success
------------------------------------------------------------------------------------
Resource Type: IPV6Enabled
        Status: success
------------------------------------------------------------------------------------
Resource Type: PriceClass
        Status: success
------------------------------------------------------------------------------------
Resource Type: Enabled
        Status: success
------------------------------------------------------------------------------------
Resource Type: Aliases
        Status: failed          Message: Empty Response
------------------------------------------------------------------------------------
Resource Type: Logging
        Status: failed          Message: Drift on - Bucket
        Status: failed          Message: Drift on - Prefix
        Status: success         Message: IncludeCookies
------------------------------------------------------------------------------------
Resource Type: ViewerCertificate
        Status: failed          Message: Drift on - MinimumProtocolVersion
------------------------------------------------------------------------------------
Resource Type: CustomErrorResponses
        Status: failed          Message: Drift - Failed all checks
------------------------------------------------------------------------------------
Resource Type: Origins
        Status: failed          Message: Drift on - Origin does not exist ELB
------------------------------------------------------------------------------------
Resource Type: CacheBehaviors
        Status: failed          Message: Drift - Failed all checks
------------------------------------------------------------------------------------
Resource Type: DefaultCacheBehavior
        Status: failed          Message: TargetOriginId
        Status: failed          Message: Compress
        Status: failed          Message: ViewerProtocolPolicy
        Status: failed          Message: Drift on - AllowedMethod OPTIONS
        Status: success         Message: MinTTL
        Status: success         Message: MaxTTL
        Status: success         Message: DefaultTTL
        Status: success         Message: SmoothStreaming
        Status: success         Message: ForwardedValues QueryString
        Status: success         Message: AllowedMethod GET
        Status: success         Message: AllowedMethod HEAD
```
## Built With

* [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) - SDK for interacting with AWS Services with python

## Authors

* **Jy Kingston** - [EonX](https://eonx.com/)

