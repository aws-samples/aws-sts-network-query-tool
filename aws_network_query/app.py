# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import sys
import csv
import os
import concurrent.futures
import boto3
import botocore
import argparse
import uuid

def str2bool(input):
    """
    validate that a boolean value has been entered
    :param input:
    :return True or False:
    """
    if isinstance(input, bool):
       return input
    if input.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif input.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def get_child_session(account_id, role_name, session=None):
    """
    get session, with error handling, allows for passing in an sts client.
    This allows Account A > B > C where A cannot assume a role directly to C
    :param account_id:
    :param role_name:
    :param session=None:
    :return session:
    """
    # “/“ + name if not name.startswith(“/“) else name
    try:
        # allow for a to b to c if given sts client.
        if session is None:
            session = boto3.session.Session()

        client = session.client('sts')

        response = client.get_caller_identity()
        # remove the first slash
        role_name = role_name[1:] if role_name.startswith("/") else role_name
        # never have a slash in front of the role name
        role_arn = 'arn:aws:iam::' + account_id + ':role/' + role_name
        print("Creating new session with role: {} from {}".format(role_arn, response['Arn']))

        response = client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='AWSNetworkQueryTool_'+str(uuid.uuid1())
        )
        credentials = response['Credentials']
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        return session
    except botocore.exceptions.ClientError as e:
        print(e)
        return 'FAILED'

def get_org_accounts(session):
    """
    return a list of all accounts in the organization
    :param session:
    :return account_ids:
    """
    org_client = session.client('organizations')
    account_ids = []
    try:
        response = org_client.list_accounts()
    except botocore.exceptions.ClientError as e:
        print(e)
        print("Please consider specifying a list of accounts using the --accounts-csv option")

    try:
        for account in response['Accounts']:
            account_ids.append(account['Id'])
        while 'NextToken' in response:
            response = org_client.list_accounts(NextToken=response['NextToken'])
            for account in response['Accounts']:
                account_ids.append(account['Id'])
        return account_ids
    except NameError:
        return None


def list_accounts_from_file(file_name):
    """
    return a list of all accounts in a csv
    :param file_name:
    :return account_ids:
    """
    print("Extracting Accounts via File Input")
    accounts = []

    with open(file_name) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=',')
        x = 0
        # keep track of the positions, since this is a user defined file
        accountIdPos = None
        for row in readCSV:
            # read in the headers
            if x == 0:
                for y in range(len(row)):
                    if row[y].lower() == 'accountid':
                        accountIdPos = y
            else:
                if accountIdPos is None:
                    print("Input needs to have at least 1 field: accountid")
                    raise ValueError("Insufficient fields in input file")
                else:
                    if len(row[accountIdPos].strip()) == 12:
                        accounts.append(row[accountIdPos].strip())
                    else:
                        print(f"Line {x} contains an invalid 12-digit accountid")
                        raise ValueError("Invalid values in input file")

            x = x + 1
    return accounts


def process_internet_gateway(account, region, ec2):
    """
    describes one or more of your internet gateways
    :param account:
    :param region:
    :param ec2 (child session):
    :return list of internet gateways:
    """
    list = []
    result = []
    response = ec2.describe_internet_gateways()
    for item in response['InternetGateways']:
        list.append(item)
    while 'NextToken' in response:
        response = ec2.describe_internet_gateways(NextToken=response['NextToken'])
        for item in response['InternetGateways']:
            list.append(item)

    for item in list:
        # Change dict of vpcs to list
        vpcs = []
        for VpcId in item['Attachments']:
            vpcs.append(VpcId['VpcId'])
        vpc_string = ",".join(vpcs)

        dict = {'AccountId': account, 'InternetGatewayId': item['InternetGatewayId'], 'VpcIds': vpc_string, 'Region': region}
        print(f'Account {account}: New Internet Gateway found {dict}')

        item['AccountId'] = account
        item['Region'] = region
        item['VpcIds'] = vpc_string
        item['QueryType'] = 'igw'

        result.append(item)

    return result


def process_nat_gateway(account, region, ec2):
    """
    describes one or more of your NAT gateways
    :param account:
    :param region:
    :param ec2 (child session):
    :return list of NAT gateways:
    """
    list = []
    result = []
    response = ec2.describe_nat_gateways()
    for item in response['NatGateways']:
        list.append(item)
    while 'NextToken' in response:
        response = ec2.describe_nat_gateways(NextToken=response['NextToken'])
        for item in response['NatGateways']:
            list.append(item)

    for item in list:
        dict = {'AccountId': account, 'NatGatewayId': item['NatGatewayId'], 'VpcId': item['VpcId'], 'SubnetId': item['SubnetId'],'Region': region}
        print(f'Account {account}: New NAT Gateway found {dict}')

        item['AccountId'] = account
        item['Region'] = region
        item['QueryType'] = 'natgw'

        result.append(item)

    return result


def process_load_balancer(account, region, elb):
    """
    describes one or more of your load balancers
    :param account:
    :param region:
    :param elb (child session):
    :return list of load balancers:
    """
    list = []
    result = []
    response = elb.describe_load_balancers()
    for item in response['LoadBalancers']:
        list.append(item)
    while 'NextToken' in response:
        response = elb.describe_load_balancers(NextToken=response['NextToken'])
        for item in response['LoadBalancers']:
            list.append(item)

    for item in list:
        dict = {'AccountId': account, 'LoadBalancerArn': item['LoadBalancerArn'], 'DNSName': item['DNSName'], 'VpcId': item['VpcId'],'Region': region}
        print(f'Account {account}: New Load Balancer found {dict}')

        item['AccountId'] = account
        item['Region'] = region
        item['QueryType'] = 'elb'

        result.append(item)

    return result


def process_vpc_cidr(account, region, ec2):
    """
    describes one or more of your VPCs
    :param account:
    :param region:
    :param ec2 (child session):
    :return list of VPCs:
    """
    list = []
    result = []
    response = ec2.describe_vpcs()
    for item in response['Vpcs']:
        list.append(item)
    while 'NextToken' in response:
        response = ec2.describe_vpcs(NextToken=response['NextToken'])
        for item in response['Vpcs']:
            list.append(item)

    for item in list:
        dict = {'AccountId': account, 'VpcId': item['VpcId'], 'CIDR': item['CidrBlock'], 'Region': region}
        print(f'Account {account}: New VPC CIDR found {dict}')

        item['AccountId'] = account
        item['Region'] = region
        item['QueryType'] = 'cidr'

        result.append(item)

    return result


def process_vpc_subnets(account, region, ec2):
    """
    describes one or more of your subnets
    :param account:
    :param region:
    :param ec2 (child session):
    :return list of subnets:
    """
    list = []
    result = []
    response = ec2.describe_subnets()
    for item in response['Subnets']:
        list.append(item)
    while 'NextToken' in response:
        response = ec2.describe_subnets(NextToken=response['NextToken'])
        for item in response['Subnets']:
            list.append(item)

    for item in list:
        dict = {'AccountId': account, 'SubnetId': item['SubnetId'], 'VpcId': item['VpcId'], 'CIDR': item['CidrBlock'], 'Region': region}
        print(f'Account {account}: New VPC subnet found {dict}')

        item['AccountId'] = account
        item['Region'] = region
        item['QueryType'] = 'subnets'

        result.append(item)

    return result


def process_addresses(account, region, ec2):
    """
    describes one or more of your elastic IPs
    :param account:
    :param region:
    :param ec2 (child session):
    :return list of EIPs:
    """
    list = []
    result = []
    response = ec2.describe_addresses()
    for item in response['Addresses']:
        list.append(item)
    while 'NextToken' in response:
        response = ec2.describe_addresses(NextToken=response['NextToken'])
        for item in response['Addresses']:
            list.append(item)

    for item in list:
        dict = {'AccountId': account, 'PublicIp': item['PublicIp'], 'Region': region}
        print(f'Account {account}: New Elastic IP found {dict}')

        item['AccountId'] = account
        item['Region'] = region
        item['QueryType'] = 'addresses'

        result.append(item)

    return result


def process_network_interfaces(account, region, ec2):
    """
    describes one or more of your elastic network interfaces
    :param account:
    :param region:
    :param ec2 (child session):
    :return list of ENIs:
    """
    list = []
    result = []
    response = ec2.describe_network_interfaces()
    for item in response['NetworkInterfaces']:
        list.append(item)
    while 'NextToken' in response:
        response = ec2.describe_network_interfaces(NextToken=response['NextToken'])
        for item in response['NetworkInterfaces']:
            list.append(item)

    for item in list:
        dict = {'AccountId': account, 'NetworkInterfaceId': item['NetworkInterfaceId'], 'PrivateIpAddress': item['PrivateIpAddress'], 'Status': item['Status'], 'SubnetId': item['SubnetId'], 'Region': region}
        print(f'Account {account}: New Network Interfaces found {dict}')

        item['AccountId'] = account
        item['Region'] = region
        item['QueryType'] = 'eni'

        result.append(item)

    return result


def worker(account, session, args, region):
    """
    function to run inside threads, new session required for each thread. caught errors when only using 1 argument
    :param account:
    :param session:
    :return:
    """
    vpc = None
    session = boto3.session.Session()

    results = []
    cannotprocess = []

    try:
        print(f"Processing Account: {account}")

        role_name = os.environ.get('RoleName', args.cross_account_role_name)
        child_session = get_child_session(account_id=account, role_name=role_name, session=session)
        if child_session != 'FAILED':
            print(f'Account {account}: AssumeRole success, querying VPC information')
            ec2 = child_session.client('ec2')

            if region is None:
                region_list = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
            else:
                region_list = [region]

            for region in region_list:
                ec2 = child_session.client('ec2', region_name=region)

                if args.internet_gateway or args.all_reports:
                    igw_results = process_internet_gateway(account, region, ec2)
                    for item in igw_results:
                        results.append(item)

                if args.nat_gateway or args.all_reports:
                    natgw_results = process_nat_gateway(account, region, ec2)
                    for item in natgw_results:
                        results.append(item)

                if args.load_balancer or args.all_reports:
                    elb = child_session.client('elbv2', region_name=region)
                    elb_results = process_load_balancer(account, region, elb)
                    for item in elb_results:
                        results.append(item)

                if args.vpc_cidr or args.all_reports:
                    cidr_results = process_vpc_cidr(account, region, ec2)
                    for item in cidr_results:
                        results.append(item)

                if args.vpc_subnets or args.all_reports:
                    subnets_results = process_vpc_subnets(account, region, ec2)
                    for item in subnets_results:
                        results.append(item)

                if args.addresses or args.all_reports:
                    addresses_results = process_addresses(account, region, ec2)
                    for item in addresses_results:
                        results.append(item)

                if args.network_interfaces or args.all_reports:
                    eni_results = process_network_interfaces(account, region, ec2)
                    for item in eni_results:
                        results.append(item)

        else:
            cannotprocess.append(account)

    except botocore.exceptions.ClientError as e:
        print(f'Account {account}: {e}')
        pass
    except Exception as e:
        print(f'Account {account}: {e}')
        raise e

    return results,cannotprocess

def get_headers(results):
    """
    getting keys from downstream result so that custom logic added after won't required updating in multiple places
    :param results:
    :return headers:
    """
    headers = []
    for d in results:
        for key in d.keys():
            headers.append(key)
    headers = list(set(headers))
    return headers


def write_csv(results, output_filename):
    """
    write to csv
    :param results:
    :return:
    """
    with open((output_filename+'.csv'), 'w') as csvfile:
        count = 0
        header = get_headers(results)
        writer = csv.DictWriter(csvfile, fieldnames=header, lineterminator='\n', extrasaction='ignore')
        writer.writeheader()
        for result in results:
            # Writing data of CSV file
            writer.writerow(result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-region", "--region", default=False, help="Report only on the specified region. Default: all regions are reported on.")
    parser.add_argument("-r", "--cross-account-role-name", default="CrossAccountRoleForAWSNetworkQueryTool", help="Enter the CrossAccountRoleName that you used in the cross-account-member-role CloudFormation template. Default: CrossAccountRoleForAWSNetworkQueryTool")
    parser.add_argument("-o", "--output-filename", default="output", help="Choose a filename for the output. Default: output.csv")
    parser.add_argument("-i", "--accounts-csv", default=False, help="Choose a CSV containing AccountIds. Default: Account IDs will be pulled from AWS Organizations")
    parser.add_argument("-igw", "--internet-gateway", type=str2bool, nargs='?', const=True, default=False, help="Activate IGW Report")
    parser.add_argument("-natgw", "--nat-gateway", type=str2bool, nargs='?', const=True, default=False, help="Activate NATGW Report")
    parser.add_argument("-elb", "--load-balancer", type=str2bool, nargs='?', const=True, default=False, help="Activate ELB Report")
    parser.add_argument("-cidr", "--vpc-cidr", type=str2bool, nargs='?', const=True, default=False, help="Activate VPC CIDR Report")
    parser.add_argument("-subnets", "--vpc-subnets", type=str2bool, nargs='?', const=True, default=False, help="Activate VPC Subnet Report")
    parser.add_argument("-eip", "--addresses", type=str2bool, nargs='?', const=True, default=False, help="Activate EIP Report")
    parser.add_argument("-eni", "--network-interfaces", type=str2bool, nargs='?', const=True, default=False, help="Activate ENI Report")
    parser.add_argument("-all", "--all-reports", type=str2bool, nargs='?', const=True, default=False, help="Activate all supported reports")
    args = parser.parse_args()

    threads = []
    threads_final_result = []
    threads_not_processed = []
    final_result_igw = []
    final_result_natgw = []
    final_result_elb = []
    final_result_cidr = []
    final_result_subnets = []
    final_result_addresses = []
    final_result_eni = []
    final_result_notprocessed = []

    if not args.internet_gateway and not args.nat_gateway \
            and not args.load_balancer and not args.vpc_cidr \
            and not args.vpc_subnets and not args.addresses \
            and not args.network_interfaces and not args.all_reports:
        print("No scans selected. Nothing to do here. Try adding the --help option")
        exit()

    session = boto3.session.Session()

    if not args.accounts_csv:
        accounts = get_org_accounts(session)
        if accounts is None:
            sys.exit(1)
    else:
        accounts = list_accounts_from_file(args.accounts_csv)

    if not args.region:
        region = None
    else:
        region = args.region
        if region is None:
            sys.exit(1)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for account in accounts:
            futures.append(executor.submit(worker, account=account, session=None, args=args, region=region))
        for future in concurrent.futures.as_completed(futures):
            future_result = future.result()
            threads_final_result.append(future_result[0])
            threads_not_processed.append(future_result[1])

    for thread_result in threads_final_result:
        for item in thread_result:
            try:
                if item['QueryType'] == 'igw':
                    final_result_igw.append(item)
                if item['QueryType'] == 'natgw':
                    final_result_natgw.append(item)
                if item['QueryType'] == 'elb':
                    final_result_elb.append(item)
                if item['QueryType'] == 'cidr':
                    final_result_cidr.append(item)
                if item['QueryType'] == 'subnets':
                    final_result_subnets.append(item)
                if item['QueryType'] == 'addresses':
                    final_result_addresses.append(item)
                if item['QueryType'] == 'eni':
                    final_result_eni.append(item)
            except (TypeError):
                pass

    for thread_result in threads_not_processed:
        try:
            if thread_result != '':
                final_result_notprocessed.append(thread_result[0])
        except (IndexError):
            pass

    print("================================")
    print("FINISHED. Results summary:")

    if args.internet_gateway or args.all_reports:
        output_filename_igw = args.output_filename + "-igw"
        print(f'A total of {len(final_result_igw)} Internet Gateways were found. Writing details to {output_filename_igw}.csv')
        write_csv(final_result_igw, output_filename_igw)

    if args.nat_gateway or args.all_reports:
        output_filename_natgw = args.output_filename + "-natgw"
        print(f'A total of {len(final_result_natgw)} NAT Gateways were found. Writing details to {output_filename_natgw}.csv')
        write_csv(final_result_natgw, output_filename_natgw)

    if args.load_balancer or args.all_reports:
        output_filename_elb = args.output_filename + "-elb"
        print(f'A total of {len(final_result_elb)} Load Balancers were found. Writing details to {output_filename_elb}.csv')
        write_csv(final_result_elb, output_filename_elb)

    if args.vpc_cidr or args.all_reports:
        output_filename_cidr = args.output_filename + "-cidr"
        print(f'A total of {len(final_result_cidr)} VPC CIDRs were found. Writing details to {output_filename_cidr}.csv')
        write_csv(final_result_cidr, output_filename_cidr)

    if args.vpc_subnets or args.all_reports:
        output_filename_subnets = args.output_filename + "-subnets"
        print(f'A total of {len(final_result_subnets)} VPC Subnets were found. Writing details to {output_filename_subnets}.csv')
        write_csv(final_result_subnets, output_filename_subnets)

    if args.addresses or args.all_reports:
        output_filename_addresses = args.output_filename + "-addresses"
        print(f'A total of {len(final_result_addresses)} Elastic IP Addresses were found. Writing details to {output_filename_addresses}.csv')
        write_csv(final_result_addresses, output_filename_addresses)

    if args.network_interfaces or args.all_reports:
        output_filename_eni = args.output_filename + "-eni"
        print(f'A total of {len(final_result_eni)} Elastic Network Interfaces were found. Writing details to {output_filename_eni}.csv')
        write_csv(final_result_eni, output_filename_eni)

    if len(final_result_notprocessed) > 0:
        final_result_notprocessedcsv = ', '.join(final_result_notprocessed)
        print(f'There were {len(final_result_notprocessed)} accounts that could not be processed: {final_result_notprocessedcsv}. Please refer to script output for more information.')


    return


if __name__ == '__main__':
    main()
