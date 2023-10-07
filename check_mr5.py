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

def get_packages_vulns( table_name, last_modified=0):
    dynamoclient = boto3.client('dynamodb', region_name='us-east-1',
                        aws_access_key_id='ASIAYJ65BCN3OBQSJUWN',
                        aws_secret_access_key='zNXwhQNY/Sa1uR94bg+UKpGEQr5eA8EoigwP80qZ',
                        aws_session_token='IQoJb3JpZ2luX2VjEGQaCXVzLWVhc3QtMSJIMEYCIQCVEQlxW8fCcELkLaNjby/8LXJFtMbz/pjCXogKbKlGfwIhALx6GLCwDLKpkswIQkAfNd+4KPnj7DvePZSxDr+2QOi7KpEDCG0QABoMNTcxMTU3MzIwNTY2Igxp3vYX/vaFxDxymJUq7gJhDeBcrPKQIt2j+o+S6AUKvrKoKpi9rvY8b5Iy2e2Fumd7IMSVP1e524H5Srh0RXWQ9/PROrIhLRjs7O7eUMSLFEPZXRj0/ePlT9qI053f6ptbBn12qZmuwUwR449K0vEbheUHvB/G9lr7wMsdJPUMFX3jT1fkZpJwkykopvUwjRR3RxlTtO2q3bIt4KvgPsz+Q8qRugPfgfjNeTHdEKNW9ofvaBTmXINN8fcM0LBBSMtzROGrCeshHOJjOk3jGScE73aTByncEB52HuSp34nB+m+yo2eW3HbwTGbg4Avr/wPsGnX+o/KoyOBPlZcKSe0QNFqaSfRoUHb7NwiX5g+qbni3S3/baJ9Y297csrZYG+dxgENdHx7XnsqdgoUmxIOZNH8OM39UZRBM+sBUg1cR2OVVGKzBTxu2YvExiSj+yF80N/nRQ/z2brODZ3dfVAVLlv1qXGqHVDZztuHikSBwIKgxZb361iBg5utiVnwwm47+qAY6pQHmpHdZQCM8LtMY+mdRn/j55+CbxO73To8zIB6pIkiSdIh0lDe9bIXcyzq6v3vz4UaIFUlduCrcO+WvSwUBqDqLVCU0TtUHNjOiBtPpLuBeZGAoG5RgSUhc/PPr5HXwSV7Q3N42XqJ8Ty8wKoE2qnjrmQ1HAJ2owje6cjy7FhcPAqJX6KooMxOsoxAickL22DqaR41u0rw2Q/SGJEfhpuBg/VZ/ydM=')
    mr_values = []
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
                                        mr_values.append([item['package_name'], cve_details])
    print(mr_values)
    print(len(mr_values))

    output_file_path = "Mr5.json"
    with open(output_file_path, 'w') as json_file:
        json.dump(mr_values, json_file, indent=4)
    print(f"DynamoDB items saved to {output_file_path}")

get_packages_vulns("vulnerable_packages-4Prod")
