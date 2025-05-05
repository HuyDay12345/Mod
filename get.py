import requests

def get_socks4_proxies():
    url = "https://www.proxy-list.download/api/v1/get?type=socks4"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            proxies = response.text.strip()
            with open("proxy.txt", "w") as f:
                f.write(proxies)
            print("Đã lưu proxy SOCKS4 vào proxy.txt")
        else:
            print("Lỗi khi lấy proxy:", response.status_code)
    except Exception as e:
        print("Lỗi:", e)

if __name__ == "__main__":
    get_socks4_proxies()