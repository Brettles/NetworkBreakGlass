#!/usr/bin/python

#
# What is this?
#  This Lambda function will probe (via HTTP or HTTPS) remote destinations and
#  if all of them are unavailable it will bring stand up a VPN connection so 
#  that connectivity can be restored. It will then send a notification via SNS
#  with the config details.
#
# WARNING:
#  This will send the preshared key for an IPSEC tunnel via SNS which could
#  well be via an unencrypted transport. Please be careful.
#
# Why would I do this?
#  Just in case everything falls apart and you need an automatic network
#  backdoor to your environment.
#
# How do I run it?
#  Set up a CloudWatch Event to run this Lambda function. You might run it
#  every 5 minutes or so.
#
# What IAM permissions does it need?
#  In addition to the basic Lambda permissions (so that CloudWatch Logs can be
#  created and written) you'll also need the following:
#   ec2:AttachVpnGateway
#   ec2:CreateTags
#   ec2:CreateVpnGateway
#   ec2:CreateCustomerGateway
#   ec2:CreateVpnConnectionRoute
#   ec2:DescribeVpnGateways
#   ec2:CreateVpnConnection
#   sns:Publish (which can be restricted to your topic ARN)
#
# How do I configure it?
#  There are a bunch of environment variables you can set to control the way
#  this function operates. They are shown below.
#  Make sure that you set the function timeout to a long enough time for
#  network operations to time out. So perhaps 60 seconds or so depending on
#  how many remote targets you're checking as the timeout for each target is
#  10 seconds so it will take that long to discover that a remote host isn't
#  responding.
#  Make sure the Lambda function runs inside a VPC (preferably the VPC you're
#  going to put the VPN into) because checking connectivity outside the VPC
#  doesn't make a lot of sense.
#  Create a SNS topic as well - you'll need that.
#
# Is there anything I should know?
#  This code uses a static CIDR block for the tunnel inside address:
#  169.254.169.248/30 - you can change it in the code if you like.
#
# Troubleshooting
#  You can run this at the command line of any Linux instance with Python and
#  boto3 installed. Set the environment variables by doing "export TARGET=xxx"
#  and so on. That way you can check that everything is working without having
#  to work within the constraints of debugging on Lambda. You should probably
#  do this on an Amazon Linux instance for compatibiltiy reasons.
#
# Environment variables:
#  TARGETS
#   Mandatory - must be set.
#   Comma separated list of IP address/hosts and port numbers to be polled.
#   Target port must be 80 (HTTP) or 443 (HTTPS).
#   If any one target responds, we consider the link in question up and no VPN will be created.
#   Example: 192.168.1.1:80,192.168.2.2:443
#
#  REMOTEIP
#   Mandatory - must be set.
#   This is the remote public IP address of your VPN server.
#   Example: 169.254.4.5
#            (yes, I'm aware that isn't a real public IP address)
#
#  VPCID
#   Mandatory - must be set.
#   This is the VPC that the VPN will be attached to.
#   Example: vpc-0b8c227ad264f7bb3
#
#  DESTINATIONCIDR
#   Mandatory - must be set.
#   This is a comma-separated list of CIDR blocks that will be added as static
#   routes to the VPN connection.
#   Example: 192.168.1.0/24,192.168.2.0/24
#
#  SNSTOPIC
#   Optional but you should set it otherwise what's the point?
#   This is the SNS topic that the VPN configuration will be sent to. If this
#   isn't set you won't get a notification.
#   Example: arn:aws:sns:ap-southeast-2:111122223333:NetworkBreakGlass
#
#  FORCEVPN
#   Optional.
#   If this environment variable is present (i.e. with any setting in it) it
#   forces the Lambda function to bring up the VPN. This is useful for
#   testing that it works.
#   Example: TRUE
#

import boto3
import logging
import os
from xml.dom import minidom
from botocore.vendored import requests

Logger = None
MyTag  = 'BreakGlass'
ConnectionTimeout = 10 # Only wait for 10 seconds for each target
CustomerConfig = None

def CheckTargets(Targets):
    global Logger,ConnectionTimeout

    TargetStates = []
    Schemas = {}
    Schemas['80'] = 'http'
    Schemas['443'] = 'https'

    TargetList = Targets.split(',')
    Logger.debug('Working with %d targets' % len(TargetList))

    for Target in TargetList:
        Logger.debug('Checking %s' % Target)

        try:
            (Address, Port) = Target.split(':')
        except:
            Logger.error('Failed to extract ADDRESS:PORT from %s' % Target)
            continue

        if Port not in Schemas:
            Logger.error('Port not listed in schemas for this to work - ignoring %s' % Target)
            continue

        Logger.info('Connecting to %s://%s' % (Schemas[Port],Address))

        try:
            Response = requests.head(Schemas[Port]+'://'+Address, timeout=ConnectionTimeout)
            Logger.info('Connect succeeded') # We actually don't care what the response is
            TargetStates.append(True)
        except Exception as e:
            Logger.info('Connect failed: %s' % str(e))
            TargetStates.append(False)

    return any(TargetStates)

def NotifyViaSNS():
    global Logger,CustomerConfig

    SNSTopic = os.getenv('SNSTOPIC')
    if SNSTopic == None:
        Logger.error('SNSTOPIC not set - cannot send notification')
        return
    Logger.debug('SNSTOPIC: %s' % SNSTopic)

    #
    # First, let's extract the pertinent information from the XML (!)
    # configuration that was passed to us when we created the VPN
    # connection. Yes this is a little ugly but it means we don't have
    # to import any libraries that aren't shipped with Lambda by default.
    #
    Logger.debug('CustomerConfig (XML): %s' % CustomerConfig)

    PresharedKeys = [] 
    AWSPublicAddresses = []
    AWSInsideAddresses = []
    CustomerInsideAddresses = []
    CustomerPublicAddresses = []

    Config = minidom.parseString(CustomerConfig)
    Tunnels = Config.getElementsByTagName('ipsec_tunnel')
    for T in Tunnels:
        try:
            PSK = T.getElementsByTagName('ike')[0].getElementsByTagName('pre_shared_key')[0].firstChild.wholeText
            CPA = T.getElementsByTagName('customer_gateway')[0].getElementsByTagName('tunnel_outside_address')[0].getElementsByTagName('ip_address')[0].firstChild.wholeText
            APA = T.getElementsByTagName('vpn_gateway')[0].getElementsByTagName('tunnel_outside_address')[0].getElementsByTagName('ip_address')[0].firstChild.wholeText
            CIA = T.getElementsByTagName('customer_gateway')[0].getElementsByTagName('tunnel_inside_address')[0].getElementsByTagName('ip_address')[0].firstChild.wholeText
            AIA = T.getElementsByTagName('vpn_gateway')[0].getElementsByTagName('tunnel_inside_address')[0].getElementsByTagName('ip_address')[0].firstChild.wholeText
        except Exception as e:
            Logger.warning('Did not extract configuration from XML: %s' % str(e))
            continue

        Logger.debug('Preshared key: %s' % PSK)
        Logger.debug('Customer public IP: %s' % CPA)
        Logger.debug('AWS public IP: %s' % APA)
        Logger.debug('Customer inside IP: %s' % CIA)
        Logger.debug('AWS inside IP: %s' % AIA)

        PresharedKeys.append(PSK)
        CustomerPublicAddresses.append(CPA)
        AWSPublicAddresses.append(APA)
        CustomerInsideAddresses.append(CIA)
        AWSInsideAddresses.append(AIA)

    #
    # Now we can tell someone what we've been doing.
    #
    if len(PresharedKeys) == 0:
        Logger.warning('Failed to extract any configuration details - notification will be empty')
        MessageText = 'No configuration details could be found - sorry about that!'
    else:
        MessageText = "Configuration details:\n\n"
        MessageText += 'Tunnel 1:\n Preshared key: %s\n AWS public IP: %s\n Your IP: %s\n AWS tunnel IP: %s\n Your tunnel IP: %s\n' % \
                       (PresharedKeys[0],AWSPublicAddresses[0],CustomerPublicAddresses[0],AWSInsideAddresses[0],CustomerInsideAddresses[0])
        if len(PresharedKeys) > 1:
            MessageText += '\nTunnel 2:\n Preshared key: %s\n AWS public IP: %s\n Your IP: %s\n AWS tunnel IP: %s\n Your tunnel IP: %s\n' % \
                           (PresharedKeys[1],AWSPublicAddresses[1],CustomerPublicAddresses[1],AWSInsideAddresses[1],CustomerInsideAddresses[1])

    Logger.info('Sending SNS notification to %s' % SNSTopic)
    Logger.debug('Message text: %s' % MessageText)

    SNS = boto3.client('sns')
    try:
        Response = SNS.publish(TopicArn=SNSTopic,
                               Subject='Network Break Glass Activated',
                               Message=MessageText)
    except Exception as e:
        Logger.warning('SNS notification failed: %s' % str(e))

    return

def TagResource(ResourceId):
    global Logger,MyTag

    EC2 = boto3.client('ec2')

    Logger.debug('Tagging resource %s' % ResourceId)

    try:
        Response = EC2.create_tags(Resources=[ResourceId], Tags=[{'Key':'Name','Value':MyTag}])
    except Exception as e:
        Logger.error('Failed to tag resource %s' % ResourceId)

#
# Only one VPG can be attached to a VPC at a time. So we first check to see if
# there is one there - if so, we return the resource id for it. If not, we
# create one and tag it appropriately.
#
def CreateOrFindVPG(VPCId):
    global Logger

    EC2 = boto3.client('ec2')
    Logger.debug('Looking for existing VPG')

    Logger.debug('Looking for existing VPG with tag %s' % MyTag)

    try:
        VPG = EC2.describe_vpn_gateways(Filters=[{'Name':'attachment.vpc-id','Values':[VPCId]}])
    except Exception as e:
        Logger.error('describe_vpn_gateways failed: %s' % str(e))
        return '' # Something bad happend - let's not try and create a VPG

    Logger.debug('Number of VPGs found: %d' % len(VPG['VpnGateways']))

    if len(VPG['VpnGateways']) > 0:
        for Gateway in VPG['VpnGateways']:
            if Gateway['State'] == 'available':
                VPGId = Gateway['VpnGatewayId']
                Logger.info('Existing VPG found: %s' % VPGId)
                return VPGId

    #
    # No VPG for this VPC so let's create one and tag it to be nice
    #
    try:
        VPGCreate = EC2.create_vpn_gateway(Type='ipsec.1')
    except Exception as e:
        Logger.error('Failed to create VPG: %s' % str(e))
        return ''

    VPGId = VPGCreate['VpnGateway']['VpnGatewayId']
    Logger.info('Created VPG: %s' % VPGId)

    TagResource(VPGId)

    Logger.debug('Attaching VPG %s to VPC %s' % (VPGId,VPCId))
    try:
        VPGAttach = EC2.attach_vpn_gateway(VpcId=VPCId, VpnGatewayId=VPGId)
    except Exception as e:
        Logger.error('Failed to attach VPG %s to VPC %s: %s' % (VPGId,VPCId,str(e)))
        return ''

    State = VPGAttach['VpcAttachment']['State']
    Logger.debug('Attachment state: %s' % State)

    if State != 'attaching' and State != 'attached':
        Logger.error('VPG attachment state is odd: %s - aborting' % State)
        return ''

    return VPGId

#
# Create the customer gateway - note that if it already exists we don't
# get an error, we are returned the id of the existing gateway.
#
def CreateCustomerGateway(RemoteIP):
    global Logger

    EC2 = boto3.client('ec2')

    Logger.debug('Creating customer gateway %s' % RemoteIP)
    try:
        CustomerGateway = EC2.create_customer_gateway(BgpAsn=65000,
                                                      PublicIp=RemoteIP,
                                                      Type='ipsec.1')
    except Exception as e:
        Logger.error('Failed to create customer gateway: %s' % str(e))
        return ''

    CGWId = CustomerGateway['CustomerGateway']['CustomerGatewayId']
    Logger.debug('Customer gateway id: %s' % CGWId)
    TagResource(CGWId)

    return CGWId 

def CreateVPNConnection(CGWId, VPGId):
    global Logger,SourceData,CustomerConfig

    CustomerConfig = None

    EC2 = boto3.client('ec2')

    Logger.debug('Creating VPN connection')
    try:
        VPNConnection = EC2.create_vpn_connection(CustomerGatewayId=CGWId,
                                                  Type='ipsec.1',
                                                  VpnGatewayId=VPGId,
                                                  Options={'StaticRoutesOnly':True})
    except Exception as e:
        Logger.error('Failed to create VPN connection: %s' % str(e))
        return ''

    VPNId = VPNConnection['VpnConnection']['VpnConnectionId']
    Logger.debug('VPN connection id: %s' % VPNId)
    TagResource(VPNId)

    CustomerConfig = VPNConnection['VpnConnection']['CustomerGatewayConfiguration']

    return VPNId

def CreateVPN():
    global Logger

    RemoteIP = os.getenv('REMOTEIP')
    if RemoteIP == None:
        Logger.error('REMOTEIP not set - cannot create VPN')
        return
    Logger.debug('REMOTEIP: %s' % RemoteIP)

    VPCId = os.getenv('VPCID')
    if VPCId == None:
        Logger.error('VPCID not set - cannot create VPN')
        return
    Logger.debug('VPCID: %s' % VPCId)

    DestinationCIDRRanges = os.getenv('DESTINATIONCIDR')
    if DestinationCIDRRanges == None:
        Logger.error('DESTINATIONCIDR not set - cannot create VPN')
        return
    Logger.debug('VPCID: %s' % VPCId)

    Logger.info('Creating VPN connection...')

    VPGId = CreateOrFindVPG(VPCId)
    if len(VPGId) == 0:
        Logger.info('Could not create or find a VPG - stopping')
        return

    CGWId = CreateCustomerGateway(RemoteIP)
    if len(CGWId) == 0:
        Logger.info('Could not create customer gateway - stopping')
        return

    VPNId = CreateVPNConnection(CGWId, VPGId)
    if len(VPNId) == 0:
        Logger.info('Could not create VPN connection - stopping')
        return

    EC2 = boto3.client('ec2')
    for Destination in DestinationCIDRRanges.split(','):
        Logger.debug('Adding static route %s' % Destination)
        try:
            StaticRoute = EC2.create_vpn_connection_route(DestinationCidrBlock=Destination,
                                                          VpnConnectionId=VPNId)
        except Exception as e:
            Logger.error('Failed to add static route: %s' % str(e))
            return

    Logger.info('Successfully created VPN connection %s' % VPNId)
    Logger.debug('Remote IP: %s' % RemoteIP)

    #
    # We're successful so notify people.
    #
    NotifyViaSNS()

    return

def lambda_handler(event, context):
    global Logger

    logging.basicConfig()
    Logger = logging.getLogger()
    Logger.setLevel(logging.INFO)

    TargetList = os.getenv('TARGETS')
    if TargetList == None :
        Logger.error('TARGETS not set - stopping')
        return False
    Logger.info('Targets: %s' % TargetList)    

    ForceVPN = os.getenv('FORCEVPN')
    if ForceVPN != None:
        Logger.info('FORCEVPN set - bringing up VPN')
        CreateVPN()
    else:
        Connectivity = CheckTargets(TargetList)
        Logger.debug('Overall connectivity is %s' % Connectivity)
        if not Connectivity:
            Logger.info('Connectivity check failed - bringing up VPN')
            CreateVPN()

    return True

if __name__ == '__main__':
    lambda_handler('', '')
