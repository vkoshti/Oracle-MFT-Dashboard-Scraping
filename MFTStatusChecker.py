import pyppdf.patch_pyppeteer
from bs4 import BeautifulSoup as bs
from lxml import html
from requests_html import HTMLSession
import requests

class MFTStatusChecker:
	#init method -- pass interval time as delay_time
	server_session = None
	def __init__(self):
		self.server_session = HTMLSession()

	def get_param_check(self,mft_properties : dict):
		check_items = ['host', 'username', 'password', 'isSecured']
		all_correct=True
		for mp in check_items:
			if mp not in mft_properties.keys():
				all_correct = False
		return all_correct
	def connection_test_to_host(self, connection_url : str):
		timeout=30
		try:
			r = requests.get(connection_url, timeout=timeout)
			return True
		except (requests.ConnectionError, requests.Timeout) as exception:
			return False

	def get_login_url(self, host : str, is_secured : bool = True):
		if is_secured:
			proto='https:'
		else:
			proto='http:'
		login_url = proto+'//'+host+'/mftconsole/faces/login'
		return login_url

	def get_authorization_url(self, host : str, is_secured : bool = True):
		if is_secured:
			proto='https:'
		else:
			proto='http:'
		auth_url = proto+'//'+host+'/mftconsole/faces/j_security_check'
		return auth_url

	def get_dashboard_url(self, host : str, is_secured : bool = True):
		if is_secured:
			proto='https:'
		else:
			proto='http:'
		dashboard_url = proto+'//'+host+'/mftconsole/faces/dashboard'
		return dashboard_url

	#method to return last file transfer status
	def configure(self,mft_properties : dict):
		if not self.get_param_check(mft_properties):
			raise Exception('Missing mandatory parameters')
		login_url = self.get_login_url(mft_properties['host'], mft_properties['isSecured'])
		if not self.connection_test_to_host(login_url):
			raise Exception('Connection failed to host: '+mft_properties['host'])
		authorization_url = self.get_authorization_url(mft_properties['host'], mft_properties['isSecured'])
		self.open_front_page(self.server_session, login_url, mft_properties)
		self.try_login(self.server_session, authorization_url, mft_properties, login_url)
		

	def get_security_headers(self, mft_properties, referal_url : str , session_id : str):
		if mft_properties['isSecured']:
			proto='https:'
		else:
			proto='http:'
		headers = {
			'Connection': 'keep-alive',
    		'Upgrade-Insecure-Requests': '1',
    		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    		'Referer': referal_url,
    		'Accept-Language': 'en-US,en;q=0.9',
    		'Origin' : proto+'//'+mft_properties['host'],
    		'Host':mft_properties['host'],
    		'Content-Type': 'application/x-www-form-urlencoded',
    		'Cookie': 'JSESSIONID='+session_id 
		}
		return headers

	def get_console_headers(self, mft_properties, referal_url : str , session_id : str):
		if mft_properties['isSecured']:
			proto='https:'
		else:
			proto='http:'
		headers = {
			'Connection': 'keep-alive',
    		'Upgrade-Insecure-Requests': '1',
    		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    		'Referer': referal_url,
    		'Accept-Language': 'en-US,en;q=0.9',
    		'Host':mft_properties['host'],
    		'Cookie': 'JSESSIONID='+session_id 
		}
		return headers

	def get_auth_payload(self, mft_properties : dict):
		auth_payload = 'j_username='+mft_properties['username']+'&j_password='+mft_properties['password']+'&j_character_encoding=UTF-8'
		return auth_payload

	def open_front_page(self, session : HTMLSession, front_page_url : str, mft_properties :dict):
		front_page = session.get(front_page_url, verify=str(mft_properties['isSecured']))

	def try_login(self, session : HTMLSession, auth_url : str, mft_properties : dict, login_url : str):
		if (not 'JSESSIONID' in session.cookies.get_dict()):
			raise Exception('Try to open login page first')
		login_page_headers=self.get_security_headers(mft_properties, login_url, session.cookies.get_dict()['JSESSIONID'])
		auth_payload = self.get_auth_payload(mft_properties)
		try:
			auth_response = session.post(auth_url, verify=str(mft_properties['isSecured']),
				headers = login_page_headers,
				data=auth_payload)
		except Exception as e:
			raise e

	def get_dashboard_page(self, mft_properties : dict):
		try:
			self.configure(mft_properties)
			dashboard_url = self.get_dashboard_url(mft_properties['host'], mft_properties['isSecured'])
			dashboard_url = dashboard_url + '?_afrLoop=154629152232405&_afrWindowMode=0&Adf-Window-Id=w10bvi9nmke&_afrFS=16&_afrMT=screen&_afrMFW=1600&_afrMFH=202&_afrMFDW=1280&_afrMFDH=720&_afrMFC=8&_afrMFCI=0&_afrMFM=0&_afrMFR=115&_afrMFG=0&_afrMFS=0&_afrMFO=0'
			dashboard_headers = self.get_console_headers(mft_properties, dashboard_url, self.server_session.cookies.get_dict()['JSESSIONID'])
			dashboard_result = self.server_session.get(dashboard_url , headers = dashboard_headers)
			new_cookies = [{
				'domain': mft_properties['host'], 
				'httpOnly': not mft_properties['isSecured'], 
				'name': 'JSESSIONID', 
				'path': '/mftconsole', 
				'secure': False, 
				'value': self.server_session.cookies.get_dict()['JSESSIONID']}]
			dashboard_result.html.render(cookies=new_cookies, scrolldown=True,
				keep_page=True,timeout=20.0,sleep=10)
			self.server_session.close()
			return dashboard_result.html
		except Exception as e:
			raise e

	def get_last_trasnfer_info(self, mft_properties):
		try:
			page_content = self.get_dashboard_page(mft_properties)
			element_list = page_content.xpath('*//td/span[@class="x221"]/text()')
			return element_list[1]
		except Exception as e:
			raise e
