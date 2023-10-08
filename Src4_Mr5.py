import json
import os
import boto3
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

def serialize(python_dict):
    serializer = TypeSerializer()
    return {k: serializer.serialize(
        v) for k, v in python_dict.items()}


def deserialize(low_level_data):
    deserializer = TypeDeserializer()
    return {k: deserializer.deserialize(
        v) for k, v in low_level_data.items()}


def lang_Check(lang, temp):
    if('_java' in temp):
        lang[2] = lang[2] + 1
    elif ('_python' in temp):
        lang[3] = lang[3] + 1
    elif ('_csharp' in temp):
        lang[1] = lang[1] + 1
    elif ('_ruby' in temp):
        lang[5] = lang[5] + 1
    elif ('_nodejs' in temp):
        lang[7] = lang[7] + 1
    elif ('_php' in temp):
        lang[4] = lang[4] + 1
    elif ('_golang' in temp):
        lang[0] = lang[0] + 1
    elif ('_jslib' in temp):
        lang[6] = lang[6] + 1


def Latest_Table():
    dynamoclient = boto3.client('dynamodb', region_name='us-east-1',
                        aws_access_key_id='',
                        aws_secret_access_key='',
                        aws_session_token='',
    paginator = dynamoclient.get_paginator('scan')
    for page in paginator.paginate(TableName='aqua_source_metadataProd'):
        for item in page.get('Items', []):
            if 'latest_vulnerability_package_table' in item:
                latest_table = item['latest_vulnerability_package_table']['S']
        break
    print(latest_table)
    get_packages_vulns(latest_table, dynamoclient)



def get_packages_vulns( table_name, dynamoclient, last_modified=0):
    mr_values = []
    src_4_data = []
    lang = [0, 0, 0, 0, 0, 0, 0, 0]
    paginator = dynamoclient.get_paginator('scan')
    for page in paginator.paginate(TableName=table_name):
        for item in page.get('Items', []):
            if 'vulns' in item:
                vulns_data = item['vulns']['M']
                for cve_details in vulns_data.items():
                    if 'AQUA' not in cve_details[0]:
                        if 'L' in cve_details[1]:
                            for entry in cve_details[1]['L']:
                                if 'M' in entry and 'mr' in entry['M']:
                                    mr_value = entry['M']['mr']['N']
                                    if(mr_value == '5'):
                                        if('src' in entry['M']):
                                            src_value = entry['M']['src']['N']
                                            if src_value == '4':
                                                src_4_data.append([item['package_name'], cve_details])
                                            else:
                                                mr_values.append([item['package_name'], cve_details])
                                                temp = item['package_name']['S']
                                                lang_Check(lang, temp)
                                        else:
                                            mr_values.append([item['package_name'], cve_details])
                                            temp = item['package_name']['S']
                                            lang_Check(lang, temp)
    print(len(mr_values))
    print(lang)
    print(len(src_4_data))

    output_file_path1 = "Src4_Mr5.json"
    with open(output_file_path1, 'w') as json_file:
        json.dump(src_4_data, json_file, indent=4)
    print(f"DynamoDB items saved to {output_file_path1}")

    output_file_path2 = "SrcNot4_Mr5.json"
    with open(output_file_path2, 'w') as json_file:
        json.dump(mr_values, json_file, indent=4)
    print(f"DynamoDB items saved to {output_file_path2}")

Latest_Table()
