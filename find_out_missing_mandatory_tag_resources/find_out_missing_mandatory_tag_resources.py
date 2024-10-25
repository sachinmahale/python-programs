import boto3

# Initialize AWS clients for us-east-2 region
ec2 = boto3.client('ec2', region_name='us-east-2')
s3 = boto3.client('s3', region_name='us-east-2')
iam = boto3.client('iam', region_name='us-east-2')
elb = boto3.client('elbv2', region_name='us-east-2')

# Required tags
required_tags = ['App', 'Env']

# Function to check for required tags and return missing ones
def check_tags(resource_id, tags, attached_instance_id=None):
    tag_keys = [tag['Key'] for tag in tags]
    missing_tags = [tag for tag in required_tags if tag not in tag_keys]
    if missing_tags:
        if attached_instance_id:
            print(f"Resource {resource_id} attached to EC2 instance {attached_instance_id} is missing tags: {', '.join(missing_tags)}")
        else:
            print(f"Resource {resource_id} is missing tags: {', '.join(missing_tags)}")

# Function to check if resource name contains 'production1'
def name_contains_production1(tags):
    for tag in tags:
        if tag['Key'] == 'Name' and 'production1' in tag['Value']:
            return True
    return False

# Function to check if VPC name contains "SYC13"
def name_contains_syc13(tags):
    for tag in tags:
        if tag['Key'] == 'Name' and 'SYC13' in tag['Value']:
            return True
    return False

# Function to check resources with 'production1' in the Name tag
def check_ec2_related_resources():
    print("Checking EC2 instances and related resources...")
    instances = ec2.describe_instances()
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            tags = instance.get('Tags', [])
            
            if name_contains_production1(tags):
                # Check and list instance if missing mandatory tags
                check_tags(instance_id, tags)
                
                # Check Network Interfaces (ENIs)
                for eni in instance['NetworkInterfaces']:
                    eni_id = eni['NetworkInterfaceId']
                    eni_tags = eni.get('TagSet', [])
                    check_tags(eni_id, eni_tags, attached_instance_id=instance_id)
                    
                    # Check Subnet for mandatory tags only if it belongs to a VPC with a name containing "syc13"
                    subnet_id = eni['SubnetId']
                    subnet = ec2.describe_subnets(SubnetIds=[subnet_id])
                    subnet_tags = subnet['Subnets'][0].get('Tags', [])
                    
                    # Describe the VPC to check its name
                    vpc_id = eni['VpcId']
                    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])
                    vpc_tags = vpc['Vpcs'][0].get('Tags', [])
                    
                    # Only check subnet tags if the VPC name contains "syc13"
                    if name_contains_production1(vpc_tags):
                        check_tags(subnet_id, subnet_tags)
                
                # Check attached EBS volumes
                volumes = ec2.describe_volumes(Filters=[{'Name': 'attachment.instance-id', 'Values': [instance_id]}])
                for volume in volumes['Volumes']:
                    volume_id = volume['VolumeId']
                    volume_tags = volume.get('Tags', [])
                    check_tags(volume_id, volume_tags, attached_instance_id=instance_id)
                
                # Check Security Groups
                for sg in instance['SecurityGroups']:
                    sg_id = sg['GroupId']
                    sg_response = ec2.describe_security_groups(GroupIds=[sg_id])
                    sg_tags = sg_response['SecurityGroups'][0].get('Tags', [])
                    check_tags(sg_id, sg_tags, attached_instance_id=instance_id)
                                # Check Route Tables associated with the instance's subnet
                for eni in instance['NetworkInterfaces']:
                    subnet_id = eni['SubnetId']
                    subnet = ec2.describe_subnets(SubnetIds=[subnet_id])
                    vpc_id = subnet['Subnets'][0]['VpcId']
                    
                    # Get VPC details to check its name
                    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])
                    vpc_tags = vpc['Vpcs'][0].get('Tags', [])

                    # Proceed if VPC name contains "syc13"
                    if name_contains_production1(vpc_tags):
                        # Describe Route Tables for this VPC
                        route_tables = ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                        for route_table in route_tables['RouteTables']:
                            route_table_id = route_table['RouteTableId']
                            route_table_tags = route_table.get('Tags', [])
                            check_tags(route_table_id, route_table_tags)

# Subnets
# def check_subnets():
#     print("Checking Subnets...")
#     subnets = ec2.describe_subnets()
#     for subnet in subnets['Subnets']:
#         subnet_id = subnet['SubnetId']
#         vpc_id = subnet['VpcId']  # Get the VPC ID associated with the subnet
#         tags = subnet.get('Tags', [])
        
#         # Describe the VPC to get its tags
#         vpc = ec2.describe_vpcs(VpcIds=[vpc_id])
#         vpc_tags = vpc['Vpcs'][0].get('Tags', [])
        
#         # Check if the VPC name contains "syc13"
#         if name_contains_syc13(vpc_tags):
#             check_tags(subnet_id, tags)


# S3 Buckets
def check_s3_bucket_tags(bucket_name, tags):
    tag_keys = [tag['Key'] for tag in tags]
    missing_tags = [tag for tag in required_tags if tag not in tag_keys]
    if missing_tags:
        print(f"S3 Bucket {bucket_name} is missing tags: {', '.join(missing_tags)}")
    else:
        print(f"S3 Bucket {bucket_name} has all mandatory tags.")

def check_s3_buckets():
    print("Checking S3 buckets...")
    buckets = s3.list_buckets()
    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        if 'production1' in bucket_name:
            try:
                bucket_tagging = s3.get_bucket_tagging(Bucket=bucket_name)
                tags = bucket_tagging.get('TagSet', [])
                
                # Check for required tags in the bucket
                check_s3_bucket_tags(bucket_name, tags)

            except s3.exceptions.NoSuchTagSet:
                print(f"S3 Bucket {bucket_name} has no tags")

# IAM Roles and their Policies
def check_iam_roles_and_policies():
    print("Checking IAM roles and attached policies...")
    roles = iam.list_roles()
    for role in roles['Roles']:
        role_name = role['RoleName']
        arn = role['Arn']
        if 'production1' in role_name:
            response = iam.list_role_tags(RoleName=role_name)
            tags = response.get('Tags', [])
            check_tags(role_name, tags)

            # Check attached policies for each role
            policies = iam.list_attached_role_policies(RoleName=role_name)
            for policy in policies['AttachedPolicies']:
                policy_arn = policy['PolicyArn']
                print(f"Checking IAM Role Policy {policy_arn}")
                policy_tags = iam.list_policy_tags(PolicyArn=policy_arn).get('Tags', [])
                check_tags(policy_arn, policy_tags)

# ELB (Elastic Load Balancers)

def check_elbs():
    print("Checking ELBs...")
    elbs = elb.describe_load_balancers()
    for load_balancer in elbs['LoadBalancers']:
        arn = load_balancer['LoadBalancerArn']
        response = elb.describe_tags(ResourceArns=[arn])
        tags = response['TagDescriptions'][0].get('Tags', [])
        
        # Check tags on the Load Balancer itself
        if name_contains_production1(tags):
            check_tags(arn, tags)

        # Check related Target Groups
        if 'TargetGroupArns' in load_balancer:
            target_group_arns = load_balancer['TargetGroupArns']
            for target_group_arn in target_group_arns:
                check_target_group_tags(target_group_arn)  # Call separate function for Target Group tag checks

        # Check related Listeners
        if 'Listeners' in load_balancer:
            listener_arns = [listener['ListenerArn'] for listener in load_balancer['Listeners']]
            for listener_arn in listener_arns:
                check_listener_tags(listener_arn)  # Call separate function for Listener tag checks

def check_target_group_tags(target_group_arn, tags):
    tag_keys = [tag['Key'] for tag in tags]
    missing_tags = [tag for tag in required_tags if tag not in tag_keys]
    if missing_tags:
        print(f"Target Group {target_group_arn} is missing tags: {', '.join(missing_tags)}")
    else:
        print(f"Target Group {target_group_arn} has all mandatory tags.")

def check_listener_tags(listener_arn, tags):
    tag_keys = [tag['Key'] for tag in tags]
    missing_tags = [tag for tag in required_tags if tag not in tag_keys]
    if missing_tags:
        print(f"Listener {listener_arn} is missing tags: {', '.join(missing_tags)}")
    else:
        print(f"Listener {listener_arn} has all mandatory tags.")

# VPCs
def check_vpcs():
    print("Checking VPCs...")
    vpcs = ec2.describe_vpcs()
    for vpc in vpcs['Vpcs']:
        vpc_id = vpc['VpcId']
        tags = vpc.get('Tags', [])
        
        # Check if the VPC name contains "SYC13"
        if name_contains_syc13(tags):
            check_tags(vpc_id, tags)

# NACLs
def check_nacls():
    print("Checking Network Access Control Lists (NACLs)...")
    nacls = ec2.describe_network_acls()
    vpcs = ec2.describe_vpcs()  # Retrieve all VPCs once for later reference
    vpc_name_mapping = {vpc['VpcId']: vpc.get('Tags', []) for vpc in vpcs['Vpcs']}  # Create a mapping of VPC IDs to their tags

    for nacl in nacls['NetworkAcls']:
        nacl_id = nacl['NetworkAclId']
        tags = nacl.get('Tags', [])
        # Get the VPC ID associated with the NACL
        vpc_id = nacl['VpcId']
        
        # Check if the VPC name contains "SYC13"
        if vpc_id in vpc_name_mapping:
            vpc_tags = vpc_name_mapping[vpc_id]
            if name_contains_syc13(vpc_tags):
                check_tags(nacl_id, tags)

# Route Tables
def check_route_tables():
    print("Checking Route Tables...")
    route_tables = ec2.describe_route_tables()
    vpcs = ec2.describe_vpcs()  # Retrieve all VPCs once for later reference
    vpc_name_mapping = {vpc['VpcId']: vpc.get('Tags', []) for vpc in vpcs['Vpcs']}  # Create a mapping of VPC IDs to their tags

    for route_table in route_tables['RouteTables']:
        route_table_id = route_table['RouteTableId']
        tags = route_table.get('Tags', [])
        # Get the VPC ID associated with the route table
        vpc_id = route_table['VpcId']
        
        # Check if the VPC name contains "SYC13"
        if vpc_id in vpc_name_mapping:
            vpc_tags = vpc_name_mapping[vpc_id]
            if name_contains_syc13(vpc_tags):
                check_tags(route_table_id, tags)

# Check Internet Gateways
def check_internet_gateways():
    print("Checking Internet Gateways...")
    igws = ec2.describe_internet_gateways()
    vpcs = ec2.describe_vpcs()  # Retrieve all VPCs once for later reference
    vpc_name_mapping = {vpc['VpcId']: vpc.get('Tags', []) for vpc in vpcs['Vpcs']}  # Create a mapping of VPC IDs to their tags

    for igw in igws['InternetGateways']:
        igw_id = igw['InternetGatewayId']
        tags = igw.get('Tags', [])
        # Get the VPC IDs associated with the Internet Gateway
        for attachment in igw['Attachments']:
            vpc_id = attachment['VpcId']
            
            # Check if the VPC name contains "SYC13"
            if vpc_id in vpc_name_mapping:
                vpc_tags = vpc_name_mapping[vpc_id]
                if name_contains_syc13(vpc_tags):
                    check_tags(igw_id, tags)

# Check NAT Gateways
def check_nat_gateways():
    print("Checking NAT Gateways...")
    nat_gateways = ec2.describe_nat_gateways()
    vpcs = ec2.describe_vpcs()  # Retrieve all VPCs once for later reference
    vpc_name_mapping = {vpc['VpcId']: vpc.get('Tags', []) for vpc in vpcs['Vpcs']}  # Create a mapping of VPC IDs to their tags

    for nat_gateway in nat_gateways['NatGateways']:
        nat_id = nat_gateway['NatGatewayId']
        tags = nat_gateway.get('Tags', [])
        
        # Get the VPC ID associated with the NAT Gateway
        vpc_id = nat_gateway.get('VpcId')
        
        # Check if the VPC ID exists in the mapping and if the name contains "SYC13"
        if vpc_id in vpc_name_mapping:
            vpc_tags = vpc_name_mapping[vpc_id]
            if name_contains_syc13(vpc_tags):
                check_tags(nat_id, tags)

# Elastic IPs (EIPs)
def check_elastic_ips():
    print("Checking Elastic IPs...")
    addresses = ec2.describe_addresses()
    vpcs = ec2.describe_vpcs()  # Retrieve all VPCs once for later reference
    vpc_name_mapping = {vpc['VpcId']: vpc.get('Tags', []) for vpc in vpcs['Vpcs']}  # Create a mapping of VPC IDs to their tags

    for address in addresses['Addresses']:
        public_ip = address['PublicIp']
        tags = address.get('Tags', [])

        # Get the association details to find the VPC ID
        association = address.get('AssociationId')
        if association:
            association_details = ec2.describe_addresses(AllocationIds=[address['AllocationId']])
            vpc_id = association_details['Addresses'][0].get('VpcId')

            # Check if the VPC ID exists in the mapping and if the name contains "SYC13"
            if vpc_id in vpc_name_mapping:
                vpc_tags = vpc_name_mapping[vpc_id]
                if name_contains_syc13(vpc_tags):
                    check_tags(public_ip, tags)

# Main function to run all checks
def main():
    check_ec2_related_resources()
    # check_subnets()
    check_s3_buckets()
    check_iam_roles_and_policies()
    check_elbs()
    check_vpcs()
    check_nacls()
    check_internet_gateways()
    check_nat_gateways()
    check_elastic_ips()

if __name__ == '__main__':
    main()
