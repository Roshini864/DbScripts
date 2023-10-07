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



def get_packages_vulns( table_name, last_modified=0):
    dynamoclient = boto3.client('dynamodb', region_name='us-east-1',
                        aws_access_key_id='ASIAYJ65BCN3FQ2MVBYF',
                        aws_secret_access_key='EsrPcsUeK5bPXJhjQeifvxT0xcql0YPTeZ61tZJu',
                        aws_session_token='IQoJb3JpZ2luX2VjEHEaCXVzLWVhc3QtMSJHMEUCIQDth3zV99QMoFE0ftomfxSKb0lX79S70eKTbiFBQnjv0wIgNaieqshlF/wQ/kSP9hrPPD1QsdNjYlPfl7ak054wOJoqkQMIehAAGgw1NzExNTczMjA1NjYiDKZnVQ06Apur5NIdTCruAo2zeNezDLNIZExgjw8NrMgCnyOphNpEYoyDEPtTTWyZQ+KYfmoaCT2PQK3z32wKUTkQLhTflrStYQ9Pxn0Ow7zTH6OFb8X+SOsJNNRJISFcULvwzoJKCvSqqhSr+uK6U/zyHiU9oRL3asG9HTjxjKcVq+XP4UljkVELjRwwiBDRaLGwXhE9/RcYZLutQkXcyT7BHWsHklH40djqojF9reFePX0PslwUFtUYwVqUQ03TJNnFvAa76Wg4QuCsisI7PmEBRotP91DPnIkphj4bVXkFCoUzjr/MOnJoDupRTX4PYxa0qwo6o1fBXuW8v2Fy3fx2HqQyWmzEBfn/US7dbPfhiTHchGS3qVKysXyZQnaJCXZWX1XhGGtDO8tiFl7jey+JwncmDqUQBUO33Q5tOeGueRyH+9TJSwUznzwgsOKn2seqr8OBq2KXZD3j/BVVliQC+un6SnqbpxsajpB8dEdzf0BEyhHgnAwoZxMVfDCL84CpBjqmAWAlGwesRT6ZjkFn2ynAxJJXWkTfAwlAPmuBYnfsUsuLfR+hYTXhU7cSbBQDFwy65VMD+1DXhkfkOJocAHeVsp58484ouCxfrRuo7szuqtPypbvpmXrhux3w2IYoI2nuYWOC1tHf6vK3+LpBRKB6EfdAKpBG+z2g2Z30t9kQsO0efcnWHs1hysjkZjkWoKWOh2IucDhHF+fvnp81lpDOOy1p5pyZ+pw=')
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
    # print(src_4_data)
    print(len(src_4_data))

    output_file_path1 = "Src4_Mr5.json"
    with open(output_file_path1, 'w') as json_file:
        json.dump(src_4_data, json_file, indent=4)
    print(f"DynamoDB items saved to {output_file_path1}")


    output_file_path2 = "SrcNot4_Mr5.json"
    with open(output_file_path2, 'w') as json_file:
        json.dump(mr_values, json_file, indent=4)
    print(f"DynamoDB items saved to {output_file_path2}")

get_packages_vulns("vulnerable_packages-4Prod")
