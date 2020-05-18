# NetworkBreakGlass
AWS Lambda function to automatically bring up VPN connection in case of network connectivity loss.

# What is this?
This Lambda function will probe (via HTTP or HTTPS) remote destinations and if all of them are unavailable it will bring stand up a VPN connection so that connectivity can be restored. It will then send a notification via SNS with the config details.

The intention is that if your Direct Connect (DX) fails and you don't want to have a permanent backup VPN connection this will create one for you. You would configure the probes to check for the reachability of services across your DX.

## WARNINGS:
If you let the AWS VPN service generate a preshared key then this utility will send generated preshared key for the IPSEC tunnels via SNS which could well be via an unencrypted transport. Please be careful. You can avoid this by specifying the preshared key that you want to use.

#### Why would I want to use this?
Just in case everything falls apart and you need an automatic network backdoor to your environment.

#### How do I run it?
Set up a CloudWatch Event to run this Lambda function. You might run it every 5 minutes or so.

#### What IAM permissions does it need?
In addition to the basic Lambda permissions (so that CloudWatch Logs can be created and written) you'll also need the following:
  ec2:AttachVpnGateway
  ec2:CreateTags
  ec2:CreateVpnGateway
  ec2:CreateCustomerGateway
  ec2:CreateVpnConnectionRoute
  ec2:DescribeVpnGateways
  ec2:CreateVpnConnection
  sns:Publish (which can be restricted to your topic ARN)

#### How do I configure it?
There are a bunch of environment variables you can set to control the way this function operates. They are shown below.

Make sure that you set the function timeout to a long enough time for network operations to time out. So perhaps 60 seconds or so depending on how many remote targets you're checking as the timeout for each target is 10 seconds so it will take that long to discover that a remote host isn't responding.

Make sure the Lambda function runs inside a VPC (preferably the VPC you're  going to put the VPN into) because checking connectivity outside the VPC doesn't make a lot of sense. Create a SNS topic as well - you'll need that.

#### Is there anything I should know?
This code uses a static CIDR block for the tunnel inside address: 169.254.169.248/30 - you can change it in the code if you like.

#### Troubleshooting
You can run this at the command line of any Linux instance running in AWS with Python and boto3 installed. Set the environment variables by doing "export TARGET=xxx" and so on. That way you can check that everything is working without having to work within the constraints of debugging on Lambda. You should probably do this on an Amazon Linux instance for compatibiltiy reasons.

## Environment variables:
#### TARGETS
  Mandatory - must be set.

  Comma separated list of IP address/hosts and port numbers to be polled. Target port must be 80 (HTTP) or 443 (HTTPS). If any one target responds, we consider the link in question up and no VPN will be created.

  Example: 192.168.1.1:80,192.168.2.2:443

#### REMOTEIP
  Mandatory - must be set.
  
  This is the remote public IP address of your VPN server.
  
  Example: 169.254.4.5 (yes, I'm aware that isn't a real public IP address)

#### PRESHAREDKEY
  Optional - use this to set up a preshared key that you will use. This is quite useful because it means your firewall/VPN termination endpoint can be preconfigured. If you do not set this the AWS service will generate a preshared key for you and you will need to configure the VPN endpoint before traffic will flow.

#### VPCID
  Mandatory - must be set.
  
  This is the VPC that the VPN will be attached to.
  
  Example: vpc-0b8c227ad264f7bb3

#### DESTINATIONCIDR
  Mandatory - must be set.
  
  This is a comma-separated list of CIDR blocks that will be added as static routes to the VPN connection.

  Example: 192.168.1.0/24,192.168.2.0/24

#### SNSTOPIC
  Optional but you should set it otherwise what's the point?
  
  This is the SNS topic that the VPN configuration will be sent to. If this isn't set you won't get a notification.
  
  Example: arn:aws:sns:ap-southeast-2:111122223333:NetworkBreakGlass

#### FORCEVPN
  Optional.
  
  If this environment variable is present (i.e. with any setting in it) it forces the Lambda function to bring up the VPN. This is useful for testing that it works.
  
  Example: TRUE
