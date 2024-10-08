import aiohttp
import asyncio
import logging
import argparse
import csv
import json
import os
import time
import re
import base64
import random
import yaml
import pandas as pd
from urllib.parse import urljoin
from bs4 import BeautifulSoup


class IDORScanner:
    def __init__(self, config):
        self.config = config
        self.results = []
        setup_logging(config['log_level'].upper())

    async def fetch_links(self, session, url):
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    links = set()
                    for link in soup.find_all(['a', 'form'], href=True):
                        full_url = urljoin(url, link.get('href', ''))
                        links.add(full_url)
                        if link.name == 'form':
                            action_url = urljoin(url, link['action'])
                            links.add(action_url)
                            for input_tag in link.find_all('input'):
                                if input_tag.get('name'):
                                    links.add((action_url, input_tag.get('name')))
                    return links
        except Exception as e:
            logging.error(f"Kesalahan saat mengambil link dari {url}: {e}")
            return set()

    async def start_crawling(self, start_urls):
        visited = set()
        to_visit = set(start_urls)
        current_depth = 0

        while to_visit and current_depth < self.config['depth']:
            logging.info(f"Crawling depth {current_depth}: {len(to_visit)} URL(s) to visit")
            async with aiohttp.ClientSession() as session:
                tasks = [self.fetch_links(session, url) for url in list(to_visit)]
                links = await asyncio.gather(*tasks)
                for link_set in links:
                    to_visit.update(link_set)
                visited.update(to_visit)
                to_visit.difference_update(visited)
            current_depth += 1

    async def start_scanning(self, start_urls):
        async with aiohttp.ClientSession() as session:
            tasks = []
            for base_url in start_urls:
                for param_name in self.config['test_parameters']:
                    tasks.append(self.test_idor(session, base_url, param_name, self.config['test_values']))
            await asyncio.gather(*tasks)

    def generate_bypass_values(self, param_values):
        bypass_values = []
        for value in param_values:
            bypass_values.extend([
                value + "1",
                value + "2",
                "invalid_value",
                "0",
                "-1",
                "random_string",
                "null",
                "undefined",
                "1; DROP TABLE users",  # SQL Injection
                "1' OR '1'='1",        # SQL Injection
                "<script>alert('XSS')</script>"  # XSS
            ])
        return bypass_values

    async def test_idor(self, session, base_url, param_name, param_values):
        async with aiohttp.ClientSession() as session:
            # Uji ID valid
            for value in param_values:
                test_url = f"{base_url}?{param_name}={value}"
                response_data = await self.make_request(session, test_url)
                if response_data:
                    self.analyze_response(response_data, test_url, param_name, value)

            # Uji nilai tambahan
            additional_test_values = [
                "1", "2", "3",  # ID yang mungkin valid
                "999999", "random_string", "null", "undefined"
            ]
            for additional_value in additional_test_values:
                test_url = f"{base_url}?{param_name}={additional_value}"
                response_data = await self.make_request(session, test_url)
                if response_data:
                    self.analyze_response(response_data, test_url, param_name, additional_value)

            # Encoding nilai
            for value in param_values:
                encoded_values = {
                    "base64": base64.b64encode(value.encode()).decode(),
                    "url": base64.urlsafe_b64encode(value.encode()).decode(),
                    "hex": value.encode().hex()
                }
                for enc_type, enc_value in encoded_values.items():
                    encoded_url = f"{base_url}?{param_name}={enc_value}"
                    response_data = await self.make_request(session, encoded_url)
                    if response_data:
                        self.analyze_response(response_data, encoded_url, param_name, enc_value)

            # Uji wildcard
            wildcard_patterns = ["*", "?"]
            for pattern in wildcard_patterns:
                wildcard_url = f"{base_url}?{param_name}={pattern}"
                response_data = await self.make_request(session, wildcard_url)
                if response_data:
                    self.analyze_response(response_data, wildcard_url, param_name, pattern)

            # Uji bypass values
            for bypass_value in self.generate_bypass_values(param_values):
                test_url = f"{base_url}?{param_name}={bypass_value}"
                response_data = await self.make_request(session, test_url)
                if response_data:
                    self.analyze_response(response_data, test_url, param_name, bypass_value)

            # Menguji dengan berbagai metode HTTP
            for method in ['POST', 'PUT', 'DELETE']:
                for value in param_values + additional_test_values:
                    modified_url = f"{base_url}?{param_name}={value}"
                    response_data = await self.make_request(session, modified_url, method=method)
                    if response_data:
                        self.analyze_response(response_data, modified_url, param_name, value)

            # Uji traversal
            traversal_patterns = ["../", "..%2F", "..\\", "..%5C"]
            for pattern in traversal_patterns:
                for value in param_values:
                    traversal_url = f"{base_url}?{param_name}={pattern}{value}"
                    response_data = await self.make_request(session, traversal_url)
                    if response_data:
                        self.analyze_response(response_data, traversal_url, param_name, pattern + value)

            # Parameter Pollution
            if len(param_values) > 1:
                pollution_url = f"{base_url}?{param_name}={param_values[0]}&{param_name}={param_values[1]}"
                response_data = await self.make_request(session, pollution_url)
                if response_data:
                    self.analyze_response(response_data, pollution_url, param_name, param_values)

            # Pengujian terhadap GraphQL
            graphql_url = f"{base_url}/graphql"
            for value in param_values + additional_test_values:
                query = json.dumps({
                    "query": f"{{ user(id: \"{value}\") {{ id name }} }}"
                })
                response_data = await self.make_request(session, graphql_url, method='POST', json=query)
                if response_data:
                    self.analyze_response(response_data, graphql_url, "id", value)

                # Uji dengan ID yang tidak valid
                invalid_query = json.dumps({
                    "query": f"{{ user(id: \"invalid_id\") {{ id name }} }}"
                })
                response_data = await self.make_request(session, graphql_url, method='POST', json=invalid_query)
                if response_data:
                    self.analyze_response(response_data, graphql_url, "id", "invalid_id")

    async def make_request(self, session, url, method='GET', json=None, headers=None):
        if headers is None:
            headers = {
                'User-Agent': random.choice(self.config['user_agents']),
                'Accept': 'application/json',
            }

        for attempt in range(self.config['retries']):
            try:
                start_time = time.time()
                if method == 'POST' and json is not None:
                    async with session.post(url, json=json, headers=headers, timeout=self.config['timeout']) as response:
                        return await self.handle_response(response, url, start_time)
                else:
                    async with session.request(method, url, headers=headers, timeout=self.config['timeout']) as response:
                        return await self.handle_response(response, url, start_time)
            except aiohttp.ClientError as e:
                logging.error(f"Kesalahan saat mengakses {url}: {e}")
                if attempt == self.config['retries'] - 1:
                    return None
            except Exception as e:
                logging.error(f"Kesalahan tidak terduga saat mengakses {url}: {e}")
                if attempt == self.config['retries'] - 1:
                    return None

    async def handle_response(self, response, url, start_time):
        response_time = time.time() - start_time
        content = await response.text()
        return {
            "url": url,
            "status": response.status,
            "response_time": response_time,
            "content": content,
            "content_length": len(content)
        }

    def analyze_response(self, response_data, test_url, param_name=None, param_value=None):
        status = response_data["status"]
        content = response_data["content"]
        response_time = response_data["response_time"]
        content_length = response_data["content_length"]

        logging.info(f"Testing URL: {test_url} with param {param_name}={param_value}")
        logging.info(f"URL {test_url} - Status: {status}, Waktu Respon: {response_time:.2f} detik, Ukuran Konten: {content_length} bytes")

        report_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "url": test_url,
            "method": 'GET',  # Bisa disesuaikan untuk permintaan POST
            "status": status,
            "response_time": response_time,
            "content_length": content_length,
            "content_preview": content[:200],  # Preview 200 karakter
            "full_content": content,
            "param_name": param_name,
            "param_value": param_value,
            "vulnerabilities": []
        }

        # Evaluasi untuk IDOR dan MFLAC
        if status in [200, 403, 404]:
            self.results.append(report_entry)

            if self.is_potential_idor(content):
                logging.warning(f"Potensi IDOR terdeteksi di {test_url}")
                report_entry["vulnerabilities"].append("IDOR")
                self.log_idor_detection(test_url, response_data, param_name, param_value)

            if self.is_potential_mflac(content):
                logging.warning(f"Potensi MFLAC terdeteksi di {test_url}")
                report_entry["vulnerabilities"].append("MFLAC")
                self.log_mflac_detection(test_url, response_data, param_name, param_value)
        else:
            logging.info(f"URL {test_url} memberikan status: {status}")

        # Tambahkan logika untuk mendeteksi pola lain yang mungkin berhubungan dengan IDOR
        if "Unauthorized" in content or "Access Denied" in content:
            report_entry["vulnerabilities"].append("Unauthorized Access")

    def is_potential_idor(self, content):
        # Deteksi pola yang lebih canggih untuk IDOR
        if re.search(r"(Unauthorized|Access Denied|Forbidden|Not Found|Invalid ID|Object Not Found|Access Granted)", content, re.IGNORECASE):
            return True
        return False

    def log_idor_detection(self, test_url, response_data, param_name, param_value):
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "url": test_url,
            "status": response_data["status"],
            "response_time": response_data["response_time"],
            "content_length": response_data["content_length"],
            "content_preview": response_data["content"][:200],  # Preview 200 karakter
            "full_content": response_data["content"],
            "param_name": param_name,
            "param_value": param_value,
            "vulnerability_type": "IDOR"
        }
        logging.info(f"IDOR terdeteksi: {json.dumps(log_entry, indent=4)}")
        with open('idor_detections.log', 'a') as log_file:
            log_file.write(f"{json.dumps(log_entry, indent=4)}\n")

    def is_potential_mflac(self, content):
        # Deteksi pola yang lebih canggih untuk MFLAC
        if re.search(r"(admin|dashboard|settings|config|profile|user)", content, re.IGNORECASE):
            return True
        return False

    def log_mflac_detection(self, test_url, response_data, param_name, param_value):
        log_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "url": test_url,
            "status": response_data["status"],
            "response_time": response_data["response_time"],
            "content_length": response_data["content_length"],
            "content_preview": response_data["content"][:200],  # Preview 200 karakter
            "full_content": response_data["content"],
            "param_name": param_name,
            "param_value": param_value,
            "vulnerability_type": "MFLAC"
        }
        logging.info(f"MFLAC terdeteksi: {json.dumps(log_entry, indent=4)}")
        with open('mflac_detections.log', 'a') as log_file:
            log_file.write(f"{json.dumps(log_entry, indent=4)}\n")

    def generate_vulnerability_report(self):
        # Menghasilkan laporan kerentanan dalam bentuk teks untuk Burp Suite Repeater
        report_data = []
        for result in self.results:
            # Siapkan format HTTP untuk laporan
            http_request = f"{result['method']} {result['url']} HTTP/1.1\n"
            http_request += "Host: example.com\n"  # Ganti dengan host yang sesuai
            http_request += "User-Agent: Mozilla/5.0\n"  # Ganti dengan User-Agent yang sesuai
            if result['method'] == 'POST':
                http_request += "Content-Type: application/x-www-form-urlencoded\n\n"
                http_request += f"{result.get('body', '')}\n"  # Tambahkan body jika ada

            # Tambahkan informasi ke laporan
            report_data.append({
                "Timestamp": result["timestamp"],
                "HTTP Request": http_request,
                "Status": result["status"],
                "Response Time (s)": result["response_time"],
                "Content Length (bytes)": result["content_length"],
                "Parameter Name": result["param_name"],
                "Parameter Value": result["param_value"],
                "Vulnerabilities": ", ".join(result["vulnerabilities"])
            })

        # Simpan laporan dalam format teks
        with open("burp_suite_report.txt", "w") as f:
            for entry in report_data:
                f.write(f"Timestamp: {entry['Timestamp']}\n")
                f.write(f"HTTP Request:\n{entry['HTTP Request']}\n")
                f.write(f"Status: {entry['Status']}\n")
                f.write(f"Response Time (s): {entry['Response Time (s)']}\n")
                f.write(f"Content Length (bytes): {entry['Content Length (bytes)']}\n")
                f.write(f"Parameter Name: {entry['Parameter Name']}\n")
                f.write(f"Parameter Value: {entry['Parameter Value']}\n")
                f.write(f"Vulnerabilities: {entry['Vulnerabilities']}\n")
                f.write("\n" + "=" * 80 + "\n\n")

        logging.info("Laporan Burp Suite telah dihasilkan: burp_suite_report.txt")

    def save_results(self, output_filename):
        # Simpan hasil pemindaian ke dalam file sesuai format yang diinginkan (misalnya JSON)
        if self.config['output_format'] == 'json':
            with open(output_filename, 'w') as json_file:
                json.dump(self.results, json_file, indent=4)
        elif self.config['output_format'] == 'csv':
            with open(output_filename, 'w', newline='') as csv_file:
                fieldnames = self.results[0].keys() if self.results else []
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                for result in self.results:
                    writer.writerow(result)
        else:
            logging.error("Format output tidak didukung. Gunakan 'json' atau 'csv'.")

def setup_logging(level):
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_file):
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

async def main():
    parser = argparse.ArgumentParser(description="Pemindaian dan Crawling URL dengan Deteksi IDOR dan MFLAC")
    parser.add_argument("--config", required=True, help="File konfigurasi dalam format YAML")
    args = parser.parse_args()

    config = load_config(args.config)
    
    if not os.path.exists(args.config):
        raise FileNotFoundError(f"File konfigurasi '{args.config}' tidak ditemukan.")
    
    scanner = IDORScanner(config)
    start_urls = [config['start_url']]
    
    # Mulai crawling dan scanning
    await scanner.start_crawling(start_urls)
    await scanner.start_scanning(start_urls)

    # Menyimpan hasil ke dalam file berdasarkan format yang dipilih
    output_filename = f"{config['output_file']}.{config['output_format']}"
    scanner.save_results(output_filename)

    # Menghasilkan laporan kerentanan dalam format teks
    scanner.generate_vulnerability_report()

    # Menghitung dan mencetak statistik pemindaian
    total_count = len(scanner.results)
    accessible_count = sum(1 for result in scanner.results if result["status"] == 200)
    failed_count = total_count - accessible_count
    logging.info(f"Pemindaian selesai. Total URL dipindai: {total_count}, Dapat diakses: {accessible_count}, Gagal: {failed_count}")

if __name__ == '__main__':
    asyncio.run(main())
