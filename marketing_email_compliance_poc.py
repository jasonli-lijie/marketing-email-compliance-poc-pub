import glob
import openai
from openai import AzureOpenAI
import re
import validators
from dotenv import dotenv_values
import requests
from bs4 import BeautifulSoup
import pandas as pd
import json
import logging
from datetime import datetime
import ssl

def find_urls(string): 
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?<<>>]))"

    url = re.findall(regex, string)
    return [x[0] for x in url]

def process_llm_response(llm_response):
    resp1,resp2,resp3,resp4 = '',False,False,False
    lines = llm_response.split('\n')
    start_line_index = -1
    for index, line in enumerate(lines):
        if ('|---' in line) and ('---|' in line) and ('----|---' in line):
            start_line_index = index
            break
    if start_line_index != -1:
        resp1 = lines[start_line_index+1].split('|')[-2].strip()
        resp3 = lines[start_line_index+3].split('|')[-2].strip()
        resp4 = lines[start_line_index+4].split('|')[-2].strip()
        if ('yes' in resp3.lower()) and ('yes' in resp4.lower()):
            resp2 = 'NO'
        else:
            resp2 = 'YES'

    return resp1,resp2,resp3.upper(),resp4.upper()

def analysis_with_llm(email_content):
    response = client.chat.completions.create(
                model=deployment_name,
                messages=[
                        {"role": "system", "content": "You are an email marketing specialist in Australia."},
                        {"role": "user", "content": """Please analysis the following marketing email content to see 1)if the email is related to a product or a service 2) if it violates Australia Spam Act 2003 or Spam Regulations 3) if the email includes the sender's identity. 4) if the email includes the link to unsubscribe or manage preference. Please make the response in a table and each response for the first question should be either product or service, and the response for last 3 questions should be either yes or no.
                        ------------------------ 
                        """ + email_content}
                    ]
                )
    resp1,resp2,resp3,resp4 = process_llm_response(response.choices[0].message.content)
    return resp1,resp2,resp3,resp4,response.choices[0].message.content
    

def process_url(url):
    url_is_valid = False
    url_is_reachable = False
    page_title = 'N/A'
    if not (url.startswith('https://') or url.startswith('http://')):
        new_url = 'https://' + url
    else:
        new_url = url
    validation = validators.url(new_url)
    if validation:
        print(f'[URL Validation Result] URL {new_url} is valid')
        logger.info(f'[URL Validation Result] URL {new_url} is valid')
        try:
            response = requests.request("GET", new_url, headers={}, data={})
            print(f'checking if {new_url} is reacheable response {response}')
            if response.status_code >= 200 and response.status_code < 400:
                print(f'To parse response from {url} with beautifulsoap!!!')
                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.title is None:
                        page_title = ''
                else:
                        page_title = soup.title.string
                # title = soup.title.string
                print(f'[URL Validation Result] {url} is reacheable. Page title: {page_title}')
                logger.info(f'[URL Validation Result] {url} is reacheable. Page title: {page_title}')
                url_is_valid = True
                url_is_reachable = True
            else:
                print(f'[URL Validation Result] URL {url} is not reacheable. Response: {response.text}')
                logger.info(f'[URL Validation Result] URL {url} is not reacheable. Response: {response.text}')
                url_is_valid = True
                url_is_reachable = False
        except:
            print(f'An exception has occured for url {url}')
    else:
        print(f'[URL Validation Result] !!! URL {url} is invalid')
        logger.info(f'[URL Validation Result] !!! URL {url} is invalid')
        url_is_valid = False
        url_is_reachable = False
    return url_is_valid, url_is_reachable, page_title


env_config = dotenv_values('gpt4o_mini.env')  ### to reduce the cost - working
client = AzureOpenAI(
    api_key=env_config.get('openai_apikey'),
    api_version=env_config.get('openai_apiversion'),
    azure_endpoint=env_config.get('openai_endpoint'),
)
ssl._create_default_https_context = ssl._create_unverified_context

deployment_name=env_config.get('deployment_name')
log_filename = 'job_log_'+datetime.now().strftime('%Y%m%d%H%M%S')+'.log'
logging.basicConfig(filename = log_filename,
                    filemode='a',
                    format='%(asctime)s, %(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    level=logging.INFO
                    )
logger = logging.getLogger(__name__)

# Defining main function
def main():
    report_all = []
    detail_report_all = []
    email_list = glob.glob('data/*.txt')
    for email in email_list:
        print(f'Processing email: \n{email}\n\n')
        with open(email, 'r', encoding='utf-8') as file:
            email_content = file.read()
        try:
            report = {}
            report['filename']=email
            logger.info(f'Processing email: {email}')
            print('=========================================================')

            resp1,resp2,resp3,resp4,detailAnalysisResult = analysis_with_llm(email_content)
            report['DetailAnalysisResult'] = detailAnalysisResult
            report['Category'] = resp1
            report['Violate_SpamAct2003'] = resp2
            report['Include_Sender_Identity'] = resp3
            report['Include_Unsubscribe_Method'] = resp4            

            urls = find_urls(email_content)
            for url in urls:
                url_is_valid, url_is_reachable, page_title = process_url(url)
                print(f'Return from url_process function: {url_is_valid} , {url_is_reachable}, {page_title}')
                detail_report_all.append({'filename': email, 'url': url, 'valid': url_is_valid, 'reachable': url_is_reachable, 'page_title': page_title})
            report_all.append(report)

        except openai.AuthenticationError as e:
            # Handle Authentication error here, e.g. invalid API key
            print(f"OpenAI API returned an Authentication Error: {e}")

        except openai.APIConnectionError as e:
            # Handle connection error here
            print(f"Failed to connect to OpenAI API: {e}")

        except openai.BadRequestError as e:
            # Handle connection error here
            print(f"Invalid Request Error: {e}")

        except openai.RateLimitError as e:
            # Handle rate limit error
            print(f"OpenAI API request exceeded rate limit: {e}")

        except openai.InternalServerError as e:
            # Handle Service Unavailable error
            print(f"Service Unavailable: {e}")

        except openai.APITimeoutError as e:
            # Handle request timeout
            print(f"Request timed out: {e}")
            
        except openai.APIError as e:
            # Handle API error here, e.g. retry or log
            print(f"OpenAI API returned an API Error: {e}")

        except:
            # Handles all other exceptions
            print("An exception has occured.")

        print(f'Summary Report is : {report_all}')
        print(f'Detail Report is : {detail_report_all}')
        pd.read_json(json.dumps(report_all)).to_csv('report/summary_report.csv', index=False)
        pd.read_json(json.dumps(detail_report_all)).to_csv('report/detail_report.csv', index=False)
        print(f'AI Model Information: api_version: {env_config.get('openai_apiversion')}, endpoint: {env_config.get('openai_endpoint')}, deployment_name: {env_config.get('deployment_name')}')
        logger.info(f'AI Model Information: api_version: {env_config.get('openai_apiversion')}, endpoint: {env_config.get('openai_endpoint')}, deployment_name: {env_config.get('deployment_name')}')
    print('\n\n *** AI-generated content may be incorrect ***\n\n')

# __name__
if __name__=="__main__":
    main()
