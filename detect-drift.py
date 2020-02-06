#!/usr/bin/env python3
import boto3
import yaml
import argparse

parser = argparse.ArgumentParser(
    description='''AWS Drift Detector. This tool takes an uploaded CloudFormation stack and
        compares its attached template to a CloudFront Distribution. It then reports
        if it finds any drift in configuration''',
    epilog="""Here may be dragons...""")
parser.add_argument('cloudfront-distribution-id', type=str, default='', help='The ID for the CloudFront Distribution')
parser.add_argument('cloudformation-stack-id', type=str, default='', help='The ID or Name for the CloudFormation Stack')
args = parser.parse_args()

##############################################################################
# Takes the arguments that were supplied via the CLI
##############################################################################
cloudfront_distribution_id = getattr(args, 'cloudfront-distribution-id')
cloudformation_stack_id = getattr(args, 'cloudformation-stack-id')

##############################################################################
# Get the Cloudfront Distribution for our given distribution ID
##############################################################################
cloudfront_response = boto3.client('cloudfront').get_distribution(
    Id=cloudfront_distribution_id
)
##############################################################################
# Get the Cloudformation Template for our given stack ID
##############################################################################
cloudformation_response = boto3.client('cloudformation').get_template(
    StackName=cloudformation_stack_id,
    TemplateStage='Processed'
)

##############################################################################
# The cloudformation template has unresolved intrinsic functions, we need to remove these.
# As its only breaking our code on the '!' at the beginning of the string, lets just strip that out.
##############################################################################
cloudformation_response = yaml.safe_load(cloudformation_response['TemplateBody'].replace('!', ''))


##############################################################################
# Function for printing any errors and the successful comparison
#
# resource type e.g. 'Origins'
# config e.g. 'CustomOrigin'
#
# This makes it easier to see where exactly the drift may have occurred.
##############################################################################
def success(resource_type, config=''):
    status = 'success'
    if config:
        report_success[resource_type][config] = status
    else:
        report_success[resource_type]['status'] = status
    return status


def error(resource_type, config=''):
    status = 'failed'
    if config:
        report_error[resource_type][config] = status
    else:
        report_error[resource_type]['status'] = status
    return status


def print_line():
    print('------------------------------------------------------------------------------------')


##############################################################################
# Function to iterate overt he two dictionary's we're storing errors and successful comparisons in
# And prints out the results in a readable way.
##############################################################################
def print_status():
    print('Status Report')
    for key in report_success.keys():
        print_line()
        print('Resource Type: {}'.format(key))
        for message, status in report_error[key].items():
            if message != 'status':
                print('\tStatus: {1:15} Message: {2:40}'.format(key, status, message))
            elif message == 'status':
                print('\tStatus: {1:15}'.format(key, status, message))
        for message, status in report_success[key].items():
            if message != 'status':
                print('\tStatus: {1:15} Message: {2:40}'.format(key, status, message))
            elif message == 'status':
                print('\tStatus: {1:15}'.format(key, status, message))


##############################################################################
# This function retrieves a list configuration options from the cloudformation template.
#  e.g. Aliases, Logging, Origins, ViewerCertificate, CacheBehaviors...
##############################################################################
def get_cloudformation_resource_names():
    cfn_keys = []
    for resource in cloudformation_response['Resources']:
        for resource_type, resource_value in cloudformation_response['Resources'][resource].items():
            if resource_type == 'Type' and resource_value == 'AWS::CloudFront::Distribution':
                cfn = cloudformation_response['Resources'][resource]
                for config_key, config_value in cfn['Properties'].items():
                    for key, value in cfn['Properties'][config_key].items():
                        cfn_keys.append(key)
                    return cfn_keys


##############################################################################
# Gets the configuration of a cloudfront distribution for a given 'resource name'
#  e.g. Aliases, Logging, Origins, ViewerCertificate, CacheBehaviors...
# Note: there is a key that we change here, its name varies between cloudfront/cloudformation
##############################################################################
def get_cloudfront_data(key_name):
    for response, response_value in cloudfront_response.items():
        if response == 'Distribution':
            for distribution_key, distribution_value in \
                    cloudfront_response['Distribution']['DistributionConfig'].items():
                # Fix the keyname for ipv6 as it changes
                if key_name == 'IPV6Enabled':
                    key_name = 'IsIPV6Enabled'
                if distribution_key == key_name:
                    if type(cloudfront_response['Distribution']['DistributionConfig'][distribution_key]) is dict:
                        if 'Items' in \
                                cloudfront_response['Distribution']['DistributionConfig'][distribution_key].keys():
                            return cloudfront_response['Distribution']['DistributionConfig'][distribution_key]['Items']
                        else:
                            return cloudfront_response['Distribution']['DistributionConfig'][distribution_key]
                    else:
                        return cloudfront_response['Distribution']['DistributionConfig'][distribution_key]


##############################################################################
# Gets the cloudformation data for each 'resource_type' or 'resource'
##############################################################################
def get_cloudformation_data(key_name):
    for distribution_resource_name in cloudformation_response['Resources']:
        for type, cloudfront_distribution_type in cloudformation_response['Resources'][
            distribution_resource_name].items():
            if type == 'Type' and cloudfront_distribution_type == 'AWS::CloudFront::Distribution':
                for resource_config_key, resource_config_value in \
                        cloudformation_response['Resources'][distribution_resource_name]['Properties'].items():
                    for key, value in cloudformation_response['Resources'][distribution_resource_name]['Properties'][
                        resource_config_key].items():
                        if key == key_name:
                            return value


##############################################################################
# Function to validate the response data, we should check the response data to ensure its sane
# before we start our comparision.
#
# Some extra keys are added once a template is deployed in a stack, so lets account for this
#  These two keys only appear on the cloudfront distribution, and not the cloudfront template
# .e.g Quantity, Items
##############################################################################
def validate_response(resource_type):
    status = ''
    if cfn_data:
        if cf_data:
            if resource_type == 'Origins' or resource_type == 'CustomErrorResponses' or resource_type == 'CacheBehaviors':
                status = ''
                return status
            if isinstance(cf_data, dict) and cf_data.get('Quantity') == 0:
                error(resource_type, config='Empty Response')
            elif isinstance(cf_data, dict) and cf_data.get('Quantity') is None:
                return status
            elif isinstance(cfn_data, str) or isinstance(cfn_data, bool):
                if cfn_data == cf_data:
                    success(resource_type)
                else:
                    error(resource_type, config=cfn_data)
            elif isinstance(cf_data, str) or isinstance(cf_data, bool):
                if cfn_data == cf_data:
                    success(resource_type)
                else:
                    error(resource_type, config=cf_data)
            elif isinstance(cfn_data, list) and isinstance(cf_data, list):
                if cfn_data == cf_data:
                    success(resource_type)
        else:
            return error(resource_type, config='No data from CloudFront')
    else:
        return error(resource_type, config='No data from CloudFormation')


##############################################################################
# Diff
# This function defines all the quirks that we need to check for.
# I have defined a few resource types and the checks we need to perform explicitly
#
# It accepts three inputs:
# resource_type, cfn_data, cf_data
# e.g. 'Aliases', cloudformation_data, cloudfront_data
##############################################################################
def diff(resource_type, cfn_data, cf_data):
    ##############################################################################
    # Enabled
    ##############################################################################
    if resource_type == 'Enabled':
        if cfn_data == cf_data:
            success(resource_type)
    ##############################################################################
    # CacheBehaviors and CustomErrorResponses
    ##############################################################################
    elif resource_type == 'CacheBehaviors' or resource_type == 'CustomErrorResponses':
        for cfn_value in cfn_data:
            cfn_keys = cfn_value.keys()
            for cf_value in cf_data:
                cf_keys = cf_value.keys()
                for cfn_key in cfn_keys:
                    for cf_key in cf_keys:
                        if str(cf_value[cf_key]) == str(cfn_value[cfn_key]):
                            success(resource_type, config=cfn_key)
    ##############################################################################
    # Logging
    ##############################################################################
    elif resource_type == 'Logging':
        for cfn_key in cfn_data:
            for cf_key in cf_data:
                if cfn_key in cf_data:
                    if cfn_key == cf_key:
                        if cf_data[cf_key] == cfn_data[cfn_key]:
                            success(resource_type, config=cfn_key)
                        elif cf_data[cf_key] != cfn_data[cfn_key]:
                            error(resource_type, config='Drift on - {}'.format(cf_key))
    ##############################################################################
    # Origins
    ##############################################################################
    elif resource_type == 'Origins':
        origin_ids = []
        for cfn_list in cfn_data:
            for cfn_key in cfn_list:
                if cfn_key == 'Id' and cfn_list[cfn_key] not in origin_ids:
                    origin_ids.append(cfn_list[cfn_key])
        for cfn_origin in cfn_data:
            for cf_origin in cf_data:
                if cf_origin['Id'] in origin_ids:
                    if cfn_origin['Id'] == cf_origin['Id']:
                        for cfn_key in cfn_origin:
                            if cfn_key == 'CustomOriginConfig':
                                for custom_origin in cfn_origin[cfn_key]:
                                    if custom_origin == 'OriginSSLProtocols':
                                        if cf_origin[cfn_key]['OriginSslProtocols']['Items'] == cfn_origin[cfn_key][
                                            custom_origin]:
                                            success(resource_type, config='CustomOrigin: {}'.format(custom_origin))
                                        elif cf_origin[cfn_key]['OriginSslProtocols']['Items'] != cfn_origin[cfn_key][
                                            custom_origin]:
                                            error(resource_type,
                                                  config='Drift on - CustomOrigin: {}'.format(custom_origin))
                                    elif custom_origin in cf_origin[cfn_key]:
                                        if cfn_origin[cfn_key][custom_origin] == cf_origin[cfn_key][custom_origin]:
                                            success(resource_type, config='CustomOrigin: {}'.format(custom_origin))
                elif cf_origin['Id'] not in origin_ids:
                    error(resource_type, config='Drift on - Origin does not exist {}'.format(cf_origin['Id']))
    ##############################################################################
    # DefaultCacheBehavior
    ##############################################################################
    elif resource_type == 'DefaultCacheBehavior':
        for cfn_key in cfn_data.keys():
            if cfn_key == 'AllowedMethods':
                if cfn_key in cf_data:
                    for allowed_method in cfn_data[cfn_key]:
                        if allowed_method in cf_data[cfn_key]['Items']:
                            success(resource_type, config='AllowedMethod {}'.format(allowed_method))
                        else:
                            error(resource_type, config='Drift on - AllowedMethod {}'.format(allowed_method))
            if cfn_key == 'ForwardedValues':
                for cfn_value in cfn_data[cfn_key]:
                    if cfn_value in cf_data[cfn_key]:
                        if cfn_data[cfn_key][cfn_value] == cf_data[cfn_key][cfn_value]:
                            success(resource_type, config='ForwardedValues {}'.format(cfn_value))
                        else:
                            error(resource_type, config='Drift on -  ForwardedValues {}'.format(cfn_value))
            elif cfn_key != 'AllowedMethods' and cfn_key != 'ForwardedValues':
                if cfn_data[cfn_key] == cf_data[cfn_key]:
                    success(resource_type, config=cfn_key)
                elif cfn_data[cfn_key] != cf_data[cfn_key]:
                    error(resource_type, config=cfn_key)
    ##############################################################################
    # ViewerCertificate
    ##############################################################################
    elif resource_type == 'ViewerCertificate':
        for cfn_key in cfn_data:
            if cfn_key == 'SslSupportMethod':
                if 'SSLSupportMethod' in cf_data:
                    if cfn_data[cfn_key] == cf_data['SSLSupportMethod']:
                        success(resource_type, config=cfn_key)
            elif cfn_key == 'AcmCertificateArn':
                if 'ACMCertificateArn' in cf_data:
                    if cfn_data[cfn_key] == cf_data['ACMCertificateArn']:
                        success(resource_type, config=cfn_key)
            elif cfn_key in cf_data:
                if cfn_data[cfn_key] == cf_data[cfn_key]:
                    success(resource_type, config=cfn_key)
                elif cfn_data[cfn_key] != cf_data[cfn_key]:
                    error(resource_type, config='Drift on - {}'.format(cfn_key))


##############################################################################
# This gets all the available keys from cloudformation and stores them as a list
##############################################################################
cfn_property_keys = get_cloudformation_resource_names()
report_success = {}
report_error = {}

##############################################################################
# This is where we iterate through each of the 'cfn_property_keys' or 'resources'
# that were found on the cloudformation template and perform our checks to find any drift
#
##############################################################################
for resource_type in cfn_property_keys:
    # Add our resource to the reports dictionary
    report_success[resource_type] = {}
    report_error[resource_type] = {}

    # Get the Cloudformation template and CloudFront Distributions.
    cfn_data = get_cloudformation_data(resource_type)
    cf_data = get_cloudfront_data(resource_type)

    # Run the data through a basic validator to ensure its sane before we move on.
    validated_data = validate_response(resource_type)

    # Attempt to diff the CloudFormation template, against the cloudfront Distributions
    # If we aren't able to diff, chances are its not a small configuration issue
    # so we will throw an exception and let the user perform a comparison
    try:
        diff(resource_type, cfn_data, cf_data)
    except Exception as e:
        error(resource_type, config='Drift - Failed all checks')

# Print out the results for the diff
print_status()
