import json
import requests
import urllib.parse
import urllib.request
from Levenshtein import distance

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
        formatted_result['Id']    = result['entry']['id']
        formatted_result['CVEId'] = result['source']['cve']['id']
        formatted_result['Risk']  = result['vulnerability']['risk']['name']
        formatted_result['Title'] = result['entry']['title']

        formatted.append(formatted_result)

    return formatted

with open('config.json') as json_data_file:
    configuration = json.load(json_data_file)

with open('cvelist.json') as json_data_file:
    cvelist = json.load(json_data_file)

latest_titles = []

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

    skip = False

    for title in latest_titles:
        max_size = max(len(title), len(vulndb_result['Title']))
        lev_distance = distance(title, vulndb_result['Title'])
        coeff = 1.0 * lev_distance / max_size

        if coeff <= 0.4:
            skip = True
            break

    cvelist.append(vulndb_result['Title'])

    if skip:
        continue

    cve_link = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name={}'.format(
        vulndb_result['CVEId'])

    exploit_link = 'https://www.exploit-db.com/search?cve={}'.format(
        vulndb_result['CVEId'])

    full_info = vulndb_request(configuration, {'id' : vulndb_result['Id'], 'details' : 1})

    inline_keyboard = []

    telegram_message = "<strong>{} ({})</strong>\n\n".format(vulndb_result['Title'], vulndb_result['CVEId'])
    telegram_message += "<strong>Summary: </strong> {}".format(full_info[0]['entry']['summary'])

    if 'advisory' in full_info[0] and 'url' in full_info[0]['advisory']:
        inline_keyboard.append({
            "text" : "Vendor 📰",
            "url" : full_info[0]['advisory']['url']
        })

    if 'exploit' in full_info[0] and 'url' in full_info[0]['exploit']:
        inline_keyboard.append({
            "text" : "Exploit 😈",
            "url" : full_info[0]['exploit']['url']
        })

    if 'countermeasure' in full_info[0] and 'patch' in full_info[0]['countermeasure'] \
        and 'url' in full_info[0]['countermeasure']['patch']:
        inline_keyboard.append({
            "text" : "Fix 👼",
            "url" : full_info[0]['countermeasure']['patch']['url']
        })

    for chat_id in configuration['ChatIDS']:
        telegram_request(configuration, 'sendMessage', {
            'chat_id': chat_id,
            'text': telegram_message,
            'parse_mode': 'html',
            'reply_markup': json.dumps({'inline_keyboard': [inline_keyboard]})
        })

with open('cvelist.json', 'w') as json_data_file:
    json_data_file.write(json.dumps(cvelist))
