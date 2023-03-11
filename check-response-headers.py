#!/usr/bin/python3
#Author: Iulian Bancau

import requests
import argparse

help_msg = "HTTP Response Header Checker.\n\n Developed by Iulian Bancau.\n\n https://github.com/a11safe"
parser = argparse.ArgumentParser(description = help_msg)
parser.add_argument("-u", "--URL", help = "URL of the page")
parser.add_argument("-dc", "--DCERT", help = "Disable SSL certificate checking | Values: yes / no")
args = parser.parse_args()

if args.URL:

    if args.DCERT:
        if args.DCERT == 'yes':
            ssl_check = True
        else:
            ssl_check = False
    else:
        ssl_check = True

    response = requests.head(args.URL, verify=ssl_check)
    # print(response.headers)

    xss_protection = response.headers.get('X-XSS-Protection')
    if xss_protection:
        print("X-XSS-Protection value:", "\t\u001B[44m[ " + xss_protection + " ]\033[0m ", " Valid value: \033[0;42m[ 1; mode=block ]\033[0m ")
    else:
        print("\033[0;41m[ * ]\033[0;91m X-XSS-Protection headers missing\033[0m")

    hsts = response.headers.get('Strict-Transport-Security')
    if hsts:
        print("Strict-Transport-Security value:", "\t\u001B[44m[ " + hsts + " ]\033[0m ", "  Valid value: \033[0;42m[ max-age=31536000; includeSubDomains; preload ]\033[0m ")
    else:
        print("\033[0;41m[ * ]\033[0;91m HTTP Strict Transport Security headers missing\033[0m")

    x_frame_options = response.headers.get('X-Frame-Options')
    if x_frame_options:
        print("X-Frame-Options value:", "\t\u001B[44m[ " + x_frame_options + " ]\033[0m ", "  Valid value: \033[0;42m[ DENY ]\033[0m ")
    else:
        print("\033[0;41m[ * ]\033[0;91m X-Frame-Options headers missing\033[0m")

    x_content_type_options = response.headers.get('X-Content-Type-Options')
    if x_content_type_options:
        print("X-Content-Type-Options value:", "\t\u001B[44m[ " + x_content_type_options + " ]\033[0m ", " Valid value: \033[0;42m[ nosniff ]\033[0m ")
    else:
        print("\033[0;41m[ * ]\033[0;91m X-Content-Type-Options headers missing\033[0m")

    x_content_security_policy = response.headers.get('Content-Security-Policy')
    if x_content_security_policy:
        print("Content-Security-Policy value:", "\t\u001B[44m[ " + x_content_security_policy + " ]\033[0m ", " Valid value: \033[0;42m[ default-src 'self'; ]\033[0m ")
    else:
        print("\033[0;41m[ * ]\033[0;91m Content-Security-Policy headers missing\033[0m")

    x_permitted_cross_domain = response.headers.get('X-Permitted-Cross-Domain-Policies')
    if x_permitted_cross_domain:
        print("X-Permitted-Cross-Domain-Policies value:", "\t\u001B[44m[ " + x_permitted_cross_domain + " ]\033[0m ", " Valid value: \033[0;42m[ master-only ]\033[0m ")
    else:
        print("\033[0;41m[ * ]\033[0;91m X-Permitted-Cross-Domain-Policies headers missing\033[0m")

    referrer_policy = response.headers.get('Referrer-Policy')
    if referrer_policy:
        print("Referrer-Policy value:", "\t\u001B[44m[ " + referrer_policy + " ]\033[0m ", " Valid value: \033[0;42m[ same-origin ]\033[0m ")
    else:
        print("\033[0;41m[ * ]\033[0;91m Referrer-Policy headers missing\033[0m")

    expect_ct = response.headers.get('Expect-CT')
    if expect_ct:
        print("Expect-CT value:", "\t\u001B[44m[ " + expect_ct + " ]\033[0m ", " Valid value: \033[0;42m[ max-age=60, report-uri=\"https://mydomain.com/report\" ]\033[0m ")
    else:
        print("\033[0;41m[ * ]\033[0;91m Expect-CT headers missing\033[0m")

    feature_policy = response.headers.get('Feature-Policy')
    if feature_policy:
        print("Feature-Policy value:", "\t\u001B[44m[ " + feature_policy + " ]\033[0m ", " Valid value: \033[0;42m[ vibrate 'none'; ]\033[0m ")
    else:
        print("\033[0;41m[ * ]\033[0;91m Feature-Policy headers missing\033[0m")
else:
    parser.print_help()

#sudo apt remove pipenv
#pip3 install pipenv
#python3 -m pipenv shell
#pipenv install
