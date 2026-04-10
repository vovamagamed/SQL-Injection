#!/usr/bin/env python3
"""
SQL Injection Security Tester - Faqat o'z web saytingizni test qilish uchun
MUHIM: Bu vosita faqat sizning ruxsatingiz bo'lgan tizimlarda ishlatilishi kerak!
"""

import requests
import time
import sys
from urllib.parse import urlparse, urljoin
import json
from datetime import datetime
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

class SQLInjectionTester:
    def __init__(self, target_url, cookie=None):
        """
        target_url: Sizning web saytingiz (masalan: http://mening-saytim.uz/product.php?id=1)
        cookie: Agar kerak bo'lsa (login bo'lish uchun)
        """
        self.target_url = target_url
        self.session = requests.Session()
        if cookie:
            self.session.cookies.update(cookie)
        self.vulnerabilities = []
        
        # Test payload'lar (faqat aniqlash uchun, zarar yetkazmaydi)
        self.test_payloads = [
            "'",                           # Error-based
            "' OR '1'='1",                # Boolean-based
            "' OR SLEEP(5)-- -",          # Time-based (xavfsiz)
            "' UNION SELECT NULL-- -",    # Union-based
            "'; SELECT * FROM users-- -", # Stacked queries
            "' AND 1=1-- -",
            "' AND 1=2-- -",
        ]
        
        # Zararsiz time-based payload (faqat test)
        self.time_payloads = [
            "' OR SLEEP(3)-- -",
            "'; WAITFOR DELAY '00:00:03'-- -",
        ]
    
    def print_banner(self):
        print(Fore.CYAN + """
╔════════════════════════════════════════════════════════╗
║     SQL Injection Security Tester v1.0                ║
║     Faqat O'ZINGIZGA TEGISHLI saytlarda ishlating!    ║
╚════════════════════════════════════════════════════════╝
        """)
    
    def test_error_based(self, param_name, original_value):
        """Error-based SQL injection test"""
        print(Fore.YELLOW + f"[*] Testing error-based injection on {param_name}...")
        
        for payload in self.test_payloads[:3]:  # First 3 payloads
            test_url = self.target_url.replace(f"{param_name}={original_value}", 
                                               f"{param_name}={original_value}{payload}")
            try:
                response = self.session.get(test_url, timeout=10)
                
                # SQL errorlarini qidirish
                sql_errors = [
                    "SQL syntax", "mysql_fetch", "ORA-[0-9]{5}", "PostgreSQL",
                    "SQLite", "Microsoft Access", "ODBC", "SQL Server",
                    "unclosed quotation mark", "You have an error in your SQL"
                ]
                
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        print(Fore.RED + f"[!] SQL INJECTION MUMKIN! - {param_name}")
                        print(Fore.RED + f"    Payload: {payload}")
                        print(Fore.RED + f"    Error: {error}")
                        return True
            except Exception as e:
                print(Fore.YELLOW + f"    Error: {e}")
        return False
    
    def test_boolean_based(self, param_name, original_value):
        """Boolean-based SQL injection test"""
        print(Fore.YELLOW + f"[*] Testing boolean-based injection on {param_name}...")
        
        true_payload = f"{original_value}' AND '1'='1"
        false_payload = f"{original_value}' AND '1'='2"
        
        try:
            # True payload
            true_url = self.target_url.replace(f"{param_name}={original_value}", 
                                              f"{param_name}={true_payload}")
            true_response = self.session.get(true_url, timeout=10)
            
            # False payload
            false_url = self.target_url.replace(f"{param_name}={original_value}", 
                                               f"{param_name}={false_payload}")
            false_response = self.session.get(false_url, timeout=10)
            
            # Agar javoblar farq qilsa - zaiflik bor
            if len(true_response.text) != len(false_response.text):
                print(Fore.RED + f"[!] BOOLEAN-BASED SQL INJECTION MUMKIN! - {param_name}")
                print(Fore.RED + f"    True payload: {true_payload}")
                print(Fore.RED + f"    False payload: {false_payload}")
                return True
        except Exception as e:
            print(Fore.YELLOW + f"    Error: {e}")
        return False
    
    def test_time_based(self, param_name, original_value):
        """Time-based SQL injection test (xavfsiz)"""
        print(Fore.YELLOW + f"[*] Testing time-based injection on {param_name}...")
        
        for payload in self.time_payloads:
            test_url = self.target_url.replace(f"{param_name}={original_value}", 
                                              f"{param_name}={original_value}{payload}")
            
            start_time = time.time()
            try:
                response = self.session.get(test_url, timeout=10)
                elapsed_time = time.time() - start_time
                
                if elapsed_time >= 2.5:  # 2.5 sekunddan ko'p bo'lsa
                    print(Fore.RED + f"[!] TIME-BASED SQL INJECTION MUMKIN! - {param_name}")
                    print(Fore.RED + f"    Delay: {elapsed_time:.2f} seconds")
                    print(Fore.RED + f"    Payload: {payload}")
                    return True
            except Exception as e:
                print(Fore.YELLOW + f"    Error: {e}")
        return False
    
    def run_full_test(self):
        """To'liq testni ishga tushirish"""
        self.print_banner()
        
        print(Fore.GREEN + f"\n[*] Testing target: {self.target_url}")
        print(Fore.YELLOW + "[!] MUHIM: Faqat o'zingizga tegishli saytni test qiling!\n")
        
        # URL dan parametrlarni ajratib olish
        if '?' not in self.target_url:
            print(Fore.RED + "[!] Error: URL da parametr bo'lishi kerak (masalan: ?id=1)")
            return
        
        base_url, params = self.target_url.split('?')
        param_pairs = params.split('&')
        
        results = []
        
        for pair in param_pairs:
            if '=' not in pair:
                continue
                
            param_name, param_value = pair.split('=', 1)
            
            print(Fore.CYAN + f"\n[+] Testing parameter: {param_name}")
            
            # Har xil testlarni o'tkazish
            vuln_found = False
            
            if self.test_error_based(param_name, param_value):
                vuln_found = True
                
            if self.test_boolean_based(param_name, param_value):
                vuln_found = True
                
            if self.test_time_based(param_name, param_value):
                vuln_found = True
            
            if vuln_found:
                results.append({
                    'parameter': param_name,
                    'url': self.target_url,
                    'timestamp': str(datetime.now())
                })
                print(Fore.RED + f"\n[!!!] XAVF! {param_name} parametrida SQL injection zaifligi bor!")
            else:
                print(Fore.GREEN + f"\n[✓] {param_name} parametri xavfsiz ko'rinadi")
        
        # Hisobot yaratish
        self.generate_report(results)
    
    def generate_report(self, results):
        """JSON formatda hisobot yaratish"""
        report = {
            'target': self.target_url,
            'test_date': str(datetime.now()),
            'vulnerabilities_found': len(results),
            'details': results,
            'recommendations': []
        }
        
        if results:
            report['recommendations'] = [
                "1. Parametrlashtirilgan so'rovlardan foydalaning",
                "2. Input validation va sanitization qo'shing",
                "3. WAF (Web Application Firewall) o'rnating",
                "4. Minimal huquqli database user ishlating",
                "5. Error handling ni yaxshilang - SQL xatolarni foydalanuvchiga ko'rsatmang"
            ]
        
        # Hisobotni saqlash
        filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(Fore.CYAN + f"\n[*] Hisobot saqlandi: {filename}")
        
        if results:
            print(Fore.RED + f"\n[!!!] {len(results)} ta zaiflik topildi!")
            print(Fore.YELLOW + "\nTavsiyalar:")
            for rec in report['recommendations']:
                print(f"  {rec}")
        else:
            print(Fore.GREEN + "\n[✓] SQL injection zaifligi topilmadi!")

def main():
    print(Fore.RED + """
    ⚠️  DIQQAT! ⚠️
    Bu vosita FAQAT o'zingizga tegishli web saytlarni test qilish uchun!
    Ruxsatsiz saytlarda ishlatish NOQONUNIY va JINOYAT hisoblanadi!
    """)
    
    response = input(Fore.YELLOW + "O'z saytingizni test qilmoqchimisiz? (ha/yo'q): ")
    
    if response.lower() != 'ha':
        print(Fore.RED + "Dastur to'xtatildi.")
        return
    
    target_url = input(Fore.CYAN + "Sayt URL ini kiriting (masalan: http://sizning-saytingiz.uz/product.php?id=1): ")
    
    # Validatsiya
    if not target_url.startswith(('http://', 'https://')):
        print(Fore.RED + "Noto'g'ri URL formati!")
        return
    
    tester = SQLInjectionTester(target_url)
    tester.run_full_test()

if __name__ == "__main__":
    main()