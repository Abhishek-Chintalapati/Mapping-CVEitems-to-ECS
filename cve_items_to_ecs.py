import requests
import json
import datetime

def get_response(url) :
    """
    Function takes url as argument and returns the response of the API
    Arguments:
        url (string): Url to get response
    Return:
        response object
    """
    return (requests.get(url))

def cve_to_ecs_mapping (cve_response) :
    """
    Function takes API response as argument then maps to the ECS schema and returns the desired JSON array
    Arguments:
        cve_response (response object): cve items
    Returns:
        json_list (list): cve to ecs mapped items list
    """
    json_list = []
    cve_dict = cve_response.json()
    cve_items = cve_dict['result']['CVE_Items']
    for cve_item in cve_items:
        ecs_schema = ecs_creation()
        date_limit = datetime.date.today() - datetime.timedelta(120)
        published_date = cve_item['publishedDate']
        published_date_obj = datetime.datetime.strptime(published_date[0:10], "%Y-%m-%d").date()
        if (date_limit < published_date_obj):
            ecs_schema['vulnerability']['enumeration'] = cve_item['cve']['data_type']
            ecs_schema['vulnerability']['id'] = cve_item['cve']['CVE_data_meta']['ID']
            ecs_schema['vulnerability']['reference'] = cve_item['cve']['references']['reference_data'][0]['url']
            ecs_schema['vulnerability']['description'] = cve_item['cve']['description']['description_data'][0]['value']
            ecs_schema['vulnerability']['score'] ['version'] = cve_item['configurations']['CVE_data_version']
            json_list.append(ecs_schema)
    return json_list

def ecs_creation():
    """
    Function creates desired ECS schema 

    """
    ecs_schema = {
        "vulnerability": {
            "enumeration": None,
            "id": None,
            "reference": None,
            "description": None,
            "score": {
                "version": None
                }
        }
    }
    return ecs_schema 

if __name__ == "__main__":
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0/"
    cve_response = get_response(url) 
    cve_items = cve_to_ecs_mapping(cve_response)
    print(json.dumps(cve_items, indent=4))