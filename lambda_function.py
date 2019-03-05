#!/usr/bin/python

import boto3
import botocore
import urllib3
import certifi
import json

api_key = ''
api_cred = ''
api_region = ''
'''
AWS Lambda handler 
It is either called as  POST request via API Gateway with a json body { 'ip_to_allow':'xxx.xxx.xxx.xxx/xx' }
or without body from a CloudWatch event
'''
def lambda_handler(event, context):
    # TODO implement
    status_code = 200
    try:
        if event['ip_to_allow'] : 
            group = update_sg('developers_ips','update developers ips in security group from API', event['ip_to_allow'])
        else :
            group = update_sg('github_hooks','automatically updated from github meta service')
        
        output = { 'statusCode': status_code, 'body' : json.dumps('Updated %s!' % group) }
    
    except botocore.exceptions.ClientError, e:
        output = { 'statusCode': e.response['ResponseMetadata']['HTTPStatusCode'],'body': json.dumps('Failed to update: %s' % e.response['Error']['Code']) }
    
    return output

'''
Update or create the security group and permissions
'''
def update_sg(groupname='', groupdesc='', ip=None):
    
    ec2 = boto3.client('ec2',api_region,aws_access_key_id=api_key, aws_secret_access_key=api_cred )
    
    try:
        sg = ec2.describe_security_groups(GroupNames=[groupname])
        gid = sg['SecurityGroups'][0]['GroupId']
    except ec2.exceptions.ClientError, e:
        print 
        if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
            sg = create_sg(ec2, groupname, groupdesc)
            gid = sg['GroupId']
        else :
            raise
    
    if ip :
        
        update(ec2, gid, ip)
    
    else :
        
        json_github =  urllib3.PoolManager(cert_reqs='CERT_REQUIRED',ca_certs=certifi.where()).request('GET','https://api.github.com/meta',headers={'user-agent':'urllib3'}).data
    
        print json_github
    
        obj = json.loads(json_github)
    
        for cidr in obj['hooks'] :
            update(ec2, gid, cidr)
        
    return groupname
                
'''
Create security group
'''
def create_sg(conn,groupname='', groupdesc=''):
    group = conn.create_security_group(GroupName=groupname,Description=groupdesc)
    print 'group %s created'% groupname
    return group    
'''
Update security group with HTTP and HTTPS permissions
'''
def update(conn,gid,cidr):
    
    try:
        conn.authorize_security_group_ingress(GroupId=gid,IpProtocol='tcp',FromPort=80,ToPort=80,CidrIp=cidr)
        conn.authorize_security_group_ingress(GroupId=gid,IpProtocol='tcp',FromPort=443,ToPort=443,CidrIp=cidr)
        
    except conn.exceptions.ClientError, e:
        if e.response['Error']['Code'] == 'InvalidPermission.Duplicate' :
            print '%s already has permission' % cidr
        else :
            raise
    return

