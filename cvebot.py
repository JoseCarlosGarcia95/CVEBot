import json
import requests
import urllib.parse
import urllib.request

def telegram_request(configuration, fname, arguments={}):
    params = urllib.parse.urlencode(arguments)
    bot_url = 'https://api.telegram.org/bot{}/{}?{}'.format(
        configuration['BotToken'], fname, params)

    return requests.get(bot_url).json()


def vulndb_request(configuration, arguments={}):
    arguments['apikey'] = configuration['VulnAPIKey']
    return requests.post('https://vuldb.com/?api', data=arguments).json()['result']

def vulndb_extract_result(results):
    formatted = []

    for result in results:
        formatted_result = {}
        formatted_result['CVEId'] = result['source']['cve']['id']
        formatted_result['Risk'] = result['vulnerability']['risk']['name']
        formatted_result['Title'] = result['entry']['title']

        formatted.append(formatted_result)

    return formatted

with open('config.json') as json_data_file:
    configuration = json.load(json_data_file)

with open('cvelist.json') as json_data_file:
    cvelist = json.load(json_data_file)

# 1. Download results from vulndb api.
raw_vulndb = vulndb_request(configuration, {'recent': 10})

# 2. Format results.
vulndb_results = vulndb_extract_result(raw_vulndb)

# 3. Send to telegram if not in cvelist.
for vulndb_result in vulndb_results:
    if vulndb_result['CVEId'] in cvelist:
        continue

    if vulndb_result['Risk'] == 'low':
        continue

    cve_link = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name={}'.format(
        vulndb_result['CVEId'])

    exploit_link = 'https://www.exploit-db.com/search?cve={}'.format(
        vulndb_result['CVEId'])

    inline_keyboard = [
        [
            {
                'text': 'CVE info',
                'url': cve_link
            },
            {
                'text': 'Search exploits',
                'url': exploit_link
            }
        ]

    ]

    telegram_message = "<strong>New vulnerability found</strong>\n\n<strong>Title: </strong>{}\n<strong>Risk: </strong> {}".format(
        vulndb_result['Title'], vulndb_result['Risk'])

    for chat_id in configuration['ChatIDS']:
        telegram_request(configuration, 'sendMessage', {
            'chat_id': chat_id,
            'text': telegram_message,
            'parse_mode': 'html',
            'reply_markup': json.dumps({'inline_keyboard': inline_keyboard})
        })

    cvelist.append(vulndb_result['CVEId'])

with open('cvelist.json', 'w') as json_data_file:
    json_data_file.write(json.dumps(cvelist))
